package openconnect

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// The gateway's own words, kept verbatim from a Cisco ASA that signs people
// in through Microsoft Entra. Every field this parses is one that gateway
// actually sends, including the ampersand it escapes inside the login
// address.
const asaSSOOffer = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg">
<tunnel-group>DefaultWEBVPNGroup</tunnel-group>
<aggauth-handle>8456446854094028006</aggauth-handle>
<auth-method>single-sign-on-v2</auth-method>
<config-hash>1775193395132</config-hash>
</opaque>
<auth id="main">
<message>Please complete the authentication process in the AnyConnect Login window.</message>
<sso-v2-login>https://vpn.corp.example/+CSCOE+/saml/sp/login?ctx=844729538&#x26;acsamlcap=v2</sso-v2-login>
<sso-v2-login-final>https://vpn.corp.example/+CSCOE+/saml_ac_login.html</sso-v2-login-final>
<sso-v2-token-cookie-name>acSamlv2Token</sso-v2-token-cookie-name>
<sso-v2-error-cookie-name>acSamlv2Error</sso-v2-error-cookie-name>
<form>
<input type="sso" name="sso-token"></input>
</form>
</auth>
</config-auth>`

// What the same gateway sends when it wants a password, which is what every
// gateway without single sign-on sends.
const asaPasswordForm = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg"><tunnel-group>DefaultWEBVPNGroup</tunnel-group></opaque>
<auth id="main">
<message>Please enter your username and password.</message>
<form method="post" action="/+webvpn+/index.html">
<input type="text" name="username" label="Username:" />
<input type="password" name="password" label="Password:" />
</form>
</auth>
</config-auth>`

// And what it sends when the token it was given does not check out.
const asaTokenRejected = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg"><tunnel-group>DefaultWEBVPNGroup</tunnel-group></opaque>
<auth id="main">
<error id="109">Single sign-on AnyConnect token verification failure.</error>
</auth>
</config-auth>`

const asaSessionIssued = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>0123456789abcdef</session-token>
<session-id>3F0A</session-id>
<auth id="success"><message>Success</message></auth>
</config-auth>`

// testClient points an ssoClient at a stand-in gateway.
func testClient(t *testing.T, handler http.HandlerFunc) (*ssoClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &ssoClient{
		base:      srv.URL,
		userAgent: ciscoUserAgent,
		version:   ciscoVersion,
		http:      &http.Client{Jar: jar, Timeout: 5 * time.Second},
	}, srv
}

func TestOfferReadsWhereToSignIn(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, asaSSOOffer)
	})

	offer, err := c.offer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if offer == nil {
		t.Fatal("a gateway offering single sign-on was read as one that wants a password")
	}
	// The escaped ampersand has to come back as one: half a query string is a
	// sign-on address that leads nowhere.
	want := "https://vpn.corp.example/+CSCOE+/saml/sp/login?ctx=844729538&acsamlcap=v2"
	if offer.LoginURL != want {
		t.Errorf("login address = %q, want %q", offer.LoginURL, want)
	}
	if offer.FinalURL != "https://vpn.corp.example/+CSCOE+/saml_ac_login.html" {
		t.Errorf("final address = %q", offer.FinalURL)
	}
	if offer.TokenCookie != "acSamlv2Token" {
		t.Errorf("token cookie = %q", offer.TokenCookie)
	}
}

// The gateway's state has to go back byte for byte. It carries the handle
// tying the browser's sign-on to this exchange, and anything reassembled
// here is a session the gateway has never heard of.
func TestOfferKeepsTheGatewaysStateVerbatim(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, asaSSOOffer)
	})

	offer, err := c.offer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(asaSSOOffer, offer.Opaque) {
		t.Fatalf("the state was rewritten rather than copied:\n%s", offer.Opaque)
	}
	if !strings.Contains(offer.Opaque, "<aggauth-handle>8456446854094028006</aggauth-handle>") {
		t.Errorf("the handle is missing from the copied state:\n%s", offer.Opaque)
	}
}

func TestAPasswordGatewayIsLeftToTheOrdinaryPath(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, asaPasswordForm)
	})

	offer, err := c.offer(context.Background())
	if err != nil {
		t.Fatalf("a plain password gateway was reported as an error: %v", err)
	}
	if offer != nil {
		t.Error("a password form was mistaken for a sign-on offer")
	}
}

// The User-Agent is the whole reason this exists: an ASA answers 404 to a
// caller it does not recognise, and openconnect reads that as "no XML login
// here" and drops to a password form that can never be satisfied.
func TestTheGatewayIsToldWhoIsCalling(t *testing.T) {
	var gotUA, gotBody string
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		io.WriteString(w, asaSSOOffer)
	})

	if _, err := c.offer(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotUA != ciscoUserAgent {
		t.Errorf("User-Agent = %q, want %q", gotUA, ciscoUserAgent)
	}
	if !strings.Contains(gotBody, "<version who=\"vpn\">"+ciscoVersion+"</version>") {
		t.Errorf("the version reported does not match the User-Agent:\n%s", gotBody)
	}
}

func TestRedeemTradesTheBrowsersCookieForASession(t *testing.T) {
	var reply string
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `type="init"`) {
			io.WriteString(w, asaSSOOffer)
			return
		}
		reply = string(body)
		io.WriteString(w, asaSessionIssued)
	})

	ctx := context.Background()
	offer, err := c.offer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := c.redeem(ctx, offer, "TOKEN-FROM-THE-BROWSER")
	if err != nil {
		t.Fatal(err)
	}

	// openconnect puts this string straight into a Cookie header, so the
	// name belongs in it.
	if cookie != "webvpn=0123456789abcdef" {
		t.Errorf("session cookie = %q", cookie)
	}
	if !strings.Contains(reply, "<sso-token>TOKEN-FROM-THE-BROWSER</sso-token>") {
		t.Errorf("the token was not sent:\n%s", reply)
	}
	if !strings.Contains(reply, offer.Opaque) {
		t.Errorf("the gateway's state was not echoed back:\n%s", reply)
	}
}

func TestARejectedSignOnSaysWhatTheGatewaySaid(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `type="init"`) {
			io.WriteString(w, asaSSOOffer)
			return
		}
		io.WriteString(w, asaTokenRejected)
	})

	ctx := context.Background()
	offer, err := c.offer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.redeem(ctx, offer, "STALE")
	if err == nil {
		t.Fatal("a rejected token was accepted")
	}
	if !strings.Contains(err.Error(), "token verification failure") {
		t.Errorf("the gateway's own words were lost: %v", err)
	}
}

// --- the session that outlives the container ------------------------------

func TestASavedSessionComesBack(t *testing.T) {
	dir := t.TempDir()
	if err := saveSession(dir, "vpn.corp.example", "alice", "webvpn=abc"); err != nil {
		t.Fatal(err)
	}
	if got := loadSession(dir, "vpn.corp.example", "alice", time.Hour); got != "webvpn=abc" {
		t.Errorf("stored session = %q, want webvpn=abc", got)
	}
}

// A session belongs to one account on one gateway. Using somebody else's is a
// login that fails in a way nobody would think to look for.
func TestASessionIsNotUsedForAnotherAccount(t *testing.T) {
	dir := t.TempDir()
	if err := saveSession(dir, "vpn.corp.example", "alice", "webvpn=abc"); err != nil {
		t.Fatal(err)
	}
	if got := loadSession(dir, "vpn.corp.example", "bob", time.Hour); got != "" {
		t.Errorf("another account's session was offered: %q", got)
	}
	if got := loadSession(dir, "other.example", "alice", time.Hour); got != "" {
		t.Errorf("another gateway's session was offered: %q", got)
	}
}

func TestAStaleSessionIsNotOffered(t *testing.T) {
	dir := t.TempDir()
	raw, err := json.Marshal(ssoSession{
		Server:   "vpn.corp.example",
		Username: "alice",
		Cookie:   "webvpn=abc",
		Obtained: time.Now().Add(-26 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sessionFile(dir), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadSession(dir, "vpn.corp.example", "alice", 24*time.Hour); got != "" {
		t.Errorf("a session past its life was offered: %q", got)
	}
}

func TestNoStoredSessionIsNotAnError(t *testing.T) {
	if got := loadSession(t.TempDir(), "vpn.corp.example", "alice", time.Hour); got != "" {
		t.Errorf("something came back from an empty directory: %q", got)
	}
	// A container without the volume mounted must not be a failure either.
	if got := loadSession(filepath.Join(t.TempDir(), "absent"), "s", "u", time.Hour); got != "" {
		t.Errorf("something came back from a missing directory: %q", got)
	}
}

func TestASessionIsForgottenOnceTheGatewayStopsHonouringIt(t *testing.T) {
	dir := t.TempDir()
	if err := saveSession(dir, "vpn.corp.example", "alice", "webvpn=abc"); err != nil {
		t.Fatal(err)
	}
	dropSession(dir)
	if got := loadSession(dir, "vpn.corp.example", "alice", time.Hour); got != "" {
		t.Errorf("a discarded session came back: %q", got)
	}
}

// --- the command line for a tunnel that is already signed in --------------

func TestASignedOnTunnelAnswersNoLoginForm(t *testing.T) {
	args := buildArgs("anyconnect", cfgWith(map[string]string{
		"authgroup": "corp", "totp_secret": testSeed,
	}), true)

	if !slices.Contains(args, "--cookie-on-stdin") {
		t.Error("--cookie-on-stdin is missing, so the session would have to go somewhere visible")
	}
	for _, unwanted := range []string{"--passwd-on-stdin", "--user=alice", "--authgroup=corp"} {
		if slices.Contains(args, unwanted) {
			t.Errorf("%q was passed for a login that has already happened", unwanted)
		}
	}
	for _, a := range args {
		if strings.HasPrefix(a, "--token-") {
			t.Errorf("%q was passed for a login that has already happened", a)
		}
	}
}

// An ASA answers 404 to a caller it does not recognise, and what follows is a
// password prompt that repeats forever. Every Cisco dial claims to be Cisco's
// own client unless the configuration says otherwise.
func TestCiscoGatewaysAreToldWhoIsCallingByDefault(t *testing.T) {
	args := buildArgs("anyconnect", cfgWith(nil), false)
	if !slices.Contains(args, "--useragent="+ciscoUserAgent) {
		t.Errorf("the default Cisco User-Agent is missing: %v", args)
	}
	if !slices.Contains(args, "--version-string="+ciscoVersion) {
		t.Errorf("the version does not match the User-Agent: %v", args)
	}
}

func TestTheOtherProtocolsAreLeftAlone(t *testing.T) {
	// Only Cisco gateways filter on this, and claiming to be Cisco's client
	// to a Fortinet gateway is a lie with nothing to gain.
	for _, a := range buildArgs("fortinet", cfgWith(nil), false) {
		if strings.HasPrefix(a, "--useragent=") || strings.HasPrefix(a, "--version-string=") {
			t.Errorf("%q was passed to a non-Cisco gateway", a)
		}
	}
}

func TestAConfiguredUserAgentWins(t *testing.T) {
	args := buildArgs("anyconnect", cfgWith(map[string]string{
		"useragent": "Something Else", "version_string": "9.9",
	}), false)
	if !slices.Contains(args, "--useragent=Something Else") {
		t.Errorf("the configured User-Agent was overridden: %v", args)
	}
	if slices.Contains(args, "--useragent="+ciscoUserAgent) {
		t.Errorf("the default was passed as well as the configured one: %v", args)
	}
	if !slices.Contains(args, "--version-string=9.9") {
		t.Errorf("the configured version was overridden: %v", args)
	}
}

// --- answering the sign-on ------------------------------------------------

func TestTheSignOnIsAnsweredInsideTheProvider(t *testing.T) {
	// No child process has been started at this point: the login happens over
	// HTTP and openconnect is handed the result, so the answer cannot go to
	// the runner's standard input the way every other answer does.
	p := &Provider{protocol: protoAnyConnect}
	ch := contract.Challenge{ID: "sso-1", Type: contract.ChallengeURL}
	answer := make(chan string, 1)
	p.ssoPending, p.ssoAnswer = &ch, answer

	if err := p.Answer(contract.AuthAnswer{ID: "sso-1", Value: " TOKEN "}); err != nil {
		t.Fatal(err)
	}
	if got := <-answer; got != "TOKEN" {
		t.Errorf("answer = %q, want the trimmed token", got)
	}
}

func TestAStaleAnswerDoesNotSatisfyAFreshSignOn(t *testing.T) {
	p := &Provider{protocol: protoAnyConnect}
	ch := contract.Challenge{ID: "sso-2", Type: contract.ChallengeURL}
	p.ssoPending, p.ssoAnswer = &ch, make(chan string, 1)

	if err := p.Answer(contract.AuthAnswer{ID: "sso-1", Value: "TOKEN"}); err == nil {
		t.Fatal("an answer to an earlier question was accepted")
	}
}

// A refused session is not a refused credential: what fixes it is another
// sign-on, so it must not park the tunnel as permanently broken.
func TestARefusedSessionIsNotTreatedAsBadCredentials(t *testing.T) {
	p := &Provider{protocol: protoAnyConnect}
	rep := &recordingReporter{}
	p.onLine("Cookie was rejected by server; exiting.", rep)

	if !p.cookieRejected.Load() {
		t.Error("a refused session was not recorded")
	}
	if p.authFailed.Load() {
		t.Error("a refused session was recorded as rejected credentials")
	}
}
