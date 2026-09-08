package openconnect

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// This file speaks the half of the AnyConnect login that openconnect cannot:
// the one where the gateway answers "sign in over there" and points at an
// identity provider's web page.
//
// A Cisco ASA with SAML offers two ways through it. In external-browser mode
// it redirects the browser back to a port on the machine the client is
// running on, which is what openconnect's --external-browser waits for. In
// the other mode -- the default, and the one every gateway seen so far is
// configured for -- it expects the client to have shown the page in a view of
// its own and to read a cookie out of it afterwards. openconnect has no such
// view, says "No SSO handler", and gives up. That is not a defeat: the login
// is plain aggregate-auth XML on either side of the browser, and the browser
// part is the one thing this project already has somewhere to put -- the
// person is sitting in front of a client with a window.
//
// So the agent does the two XML exchanges itself and asks the client for the
// one value it cannot get: init, which returns the sign-on address and an
// opaque blob; then auth-reply, which trades the cookie the browser collected
// for a session the tunnel can be built on. openconnect is handed that
// session with --cookie and never sees the login at all.

const (
	// ciscoUserAgent is what the gateway is told is calling.
	//
	// This is not cosmetic. An ASA answers the aggregate-auth POST with 404
	// when the User-Agent is not a client it recognises, and openconnect
	// reads that 404 as "no XML login here" and falls back to scraping the
	// legacy HTML form at /+webvpn+/index.html. On a SAML gateway that form
	// still renders and still takes a password, but the tunnel group behind
	// it has no password authentication at all: every submission comes back
	// as the same blank form. What a person sees is a password prompt that
	// repeats forever, which looks exactly like a wrong password and is not.
	ciscoUserAgent = "AnyConnect Linux_64 4.10.05111"
	// ciscoVersion is what goes in <version who="vpn">, kept consistent with
	// the User-Agent because a client claiming to be two different things is
	// the sort of thing a gateway is entitled to refuse.
	ciscoVersion = "4.10.05111"
)

// ssoOffer is what the gateway said when asked how to log in.
type ssoOffer struct {
	// Opaque is the gateway's own state, echoed back verbatim in the reply.
	// It carries the handle that ties the browser's sign-on to this
	// exchange, which is why it is copied rather than rebuilt: anything this
	// side invents is a session the gateway has never heard of.
	Opaque string
	// LoginURL is the page the person signs in on.
	LoginURL string
	// FinalURL is where that page ends up when it worked.
	FinalURL string
	// TokenCookie is the cookie the gateway leaves on FinalURL's origin.
	TokenCookie string
	// ErrorCookie is what it leaves there instead when the sign-on failed.
	ErrorCookie string
}

// ssoSession is a login that has already been paid for.
//
// It is written to the tunnel's own /data, which outlives the container, so
// recreating one does not cost another round of somebody's phone. Nothing
// else in here is worth keeping: the cookie is the whole session.
type ssoSession struct {
	Server   string    `json:"server"`
	Username string    `json:"username"`
	Cookie   string    `json:"cookie"`
	Obtained time.Time `json:"obtained_at"`
}

// opaqueRE lifts the gateway's blob out of the response without parsing it.
//
// It has to go back byte for byte. Decoding and re-encoding it would be a
// re-rendering, and the elements inside it are not ours to normalise.
var opaqueRE = regexp.MustCompile(`(?s)<opaque is-for="sg">.*?</opaque>`)

// authResponse is as much of the gateway's XML as this needs to read.
type authResponse struct {
	XMLName      xml.Name `xml:"config-auth"`
	Type         string   `xml:"type,attr"`
	SessionToken string   `xml:"session-token"`
	SessionID    string   `xml:"session-id"`
	Auth         struct {
		ID            string `xml:"id,attr"`
		Message       string `xml:"message"`
		SSOLogin      string `xml:"sso-v2-login"`
		SSOLoginFinal string `xml:"sso-v2-login-final"`
		TokenCookie   string `xml:"sso-v2-token-cookie-name"`
		ErrorCookie   string `xml:"sso-v2-error-cookie-name"`
		Error         struct {
			ID   string `xml:"id,attr"`
			Text string `xml:",chardata"`
		} `xml:"error"`
	} `xml:"auth"`
	Error struct {
		ID   string `xml:"id,attr"`
		Text string `xml:",chardata"`
	} `xml:"error"`
}

// ssoClient talks aggregate-auth XML to one gateway.
type ssoClient struct {
	base      string
	userAgent string
	version   string
	http      *http.Client
}

// newSSOClient prepares the exchange. The cookie jar matters: the gateway
// hands out a tunnel-group cookie on the first request and expects it on the
// second, and a client without a jar is a different visitor each time.
func newSSOClient(server, port, userAgent, version string) (*ssoClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	base := "https://" + server
	if port != "" && port != "443" {
		base += ":" + port
	}
	return &ssoClient{
		base:      base,
		userAgent: userAgent,
		version:   version,
		http: &http.Client{
			Jar: jar,
			// Long enough for a gateway on the other side of a slow link,
			// short enough that a dial does not hang on one that is gone.
			Timeout: 30 * time.Second,
			// Redirects are the gateway telling a browser where to go. This
			// is not a browser, and following them turns a readable answer
			// into whatever the login page happens to serve.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// post sends one aggregate-auth document and decodes the answer.
func (c *ssoClient) post(ctx context.Context, body string) (*authResponse, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/", strings.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	req.Header.Set("X-Transcend-Version", "1")
	req.Header.Set("X-Aggregate-Auth", "1")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, string(raw), fmt.Errorf("the gateway answered %s to the login request", resp.Status)
	}
	var out authResponse
	if err := xml.Unmarshal(raw, &out); err != nil {
		return nil, string(raw), fmt.Errorf("the gateway's login answer is not aggregate-auth XML: %w", err)
	}
	return &out, string(raw), nil
}

// offer asks the gateway how it wants to be logged into.
//
// A nil offer and a nil error means it asked for a password like any other
// gateway, and the ordinary openconnect path handles it from here.
func (c *ssoClient) offer(ctx context.Context) (*ssoOffer, error) {
	body := xmlHeader + `<config-auth client="vpn" type="init" aggregate-auth-version="2">` +
		`<version who="vpn">` + xmlEscape(c.version) + `</version>` +
		`<device-id>linux-64</device-id>` +
		`<capabilities><auth-method>single-sign-on-v2</auth-method></capabilities>` +
		`<group-access>` + xmlEscape(c.base+"/") + `</group-access>` +
		`</config-auth>`

	resp, raw, err := c.post(ctx, body)
	if err != nil {
		return nil, err
	}
	if resp.Error.Text != "" {
		return nil, fmt.Errorf("the gateway refused the login request: %s", strings.TrimSpace(resp.Error.Text))
	}
	if resp.Auth.SSOLogin == "" {
		// Not a single sign-on gateway, or not one for this client.
		return nil, nil
	}
	opaque := opaqueRE.FindString(raw)
	if opaque == "" {
		return nil, errors.New("the gateway offered single sign-on without the state to complete it")
	}
	return &ssoOffer{
		Opaque:      opaque,
		LoginURL:    resp.Auth.SSOLogin,
		FinalURL:    resp.Auth.SSOLoginFinal,
		TokenCookie: firstNonEmpty(resp.Auth.TokenCookie, "acSamlv2Token"),
		ErrorCookie: resp.Auth.ErrorCookie,
	}, nil
}

// redeem trades the cookie the browser collected for a session cookie the
// tunnel can be built on.
func (c *ssoClient) redeem(ctx context.Context, offer *ssoOffer, token string) (string, error) {
	body := xmlHeader + `<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">` +
		`<version who="vpn">` + xmlEscape(c.version) + `</version>` +
		`<device-id>linux-64</device-id>` +
		`<session-token></session-token><session-id></session-id>` +
		offer.Opaque +
		`<auth><sso-token>` + xmlEscape(token) + `</sso-token></auth>` +
		`</config-auth>`

	resp, _, err := c.post(ctx, body)
	if err != nil {
		return "", err
	}
	if msg := strings.TrimSpace(resp.Auth.Error.Text); msg != "" {
		return "", fmt.Errorf("the gateway rejected the sign-on: %s", msg)
	}
	if msg := strings.TrimSpace(resp.Error.Text); msg != "" {
		return "", fmt.Errorf("the gateway rejected the sign-on: %s", msg)
	}
	if resp.SessionToken == "" {
		return "", errors.New("the gateway accepted the sign-on but issued no session")
	}
	// openconnect wants the cookie as the gateway would have set it, name
	// included: that string is what it puts back in the Cookie header when it
	// asks for the tunnel.
	return "webvpn=" + resp.SessionToken, nil
}

const xmlHeader = `<?xml version="1.0" encoding="UTF-8"?>`

// xmlEscape keeps a value that came from configuration from ending the
// element it is written into.
func xmlEscape(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return ""
	}
	return b.String()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// --- the session that outlives the container ------------------------------

// sessionFile is where a redeemed session is kept.
//
// /data is the tunnel's own directory on the server, mounted in. It survives
// the container being recreated, which is the whole point: a login that cost
// somebody a text message should not be spent again because an image was
// pulled.
func sessionFile(dir string) string { return filepath.Join(dir, "anyconnect-session.json") }

// loadSession returns a stored session for this gateway and account, or an
// empty string when there is nothing usable.
//
// Anything unreadable, stale, or belonging to a different account is treated
// as absent rather than as an error. The cost of ignoring a good session is
// one sign-on; the cost of using somebody else's is a login that fails in a
// way nobody would think to look for.
func loadSession(dir, server, username string, ttl time.Duration) string {
	raw, err := os.ReadFile(sessionFile(dir))
	if err != nil {
		return ""
	}
	var s ssoSession
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	if s.Server != server || s.Username != username || s.Cookie == "" {
		return ""
	}
	if ttl > 0 && time.Since(s.Obtained) > ttl {
		return ""
	}
	return s.Cookie
}

// saveSession records a session so the next dial costs nothing.
func saveSession(dir, server, username, cookie string) error {
	raw, err := json.Marshal(ssoSession{
		Server:   server,
		Username: username,
		Cookie:   cookie,
		Obtained: time.Now(),
	})
	if err != nil {
		return err
	}
	// 0600: this file is a working login to a corporate network. The
	// directory is shared with the host, so the mode is the only thing
	// standing between it and anything else that can read that volume.
	return os.WriteFile(sessionFile(dir), raw, 0o600)
}

// dropSession forgets a session the gateway no longer honours, so the next
// dial asks a person rather than failing the same way again.
func dropSession(dir string) { _ = os.Remove(sessionFile(dir)) }
