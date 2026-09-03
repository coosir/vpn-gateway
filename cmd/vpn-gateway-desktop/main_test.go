//go:build desktop

package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
)

func TestPickLanguage(t *testing.T) {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		t.Setenv(k, "")
	}

	if got := pickLanguage("en"); got != "en" {
		t.Errorf("an explicit choice was ignored: %q", got)
	}
	if got := pickLanguage("klingon"); got != "zh" {
		t.Errorf("an unknown choice should fall back to the default, got %q", got)
	}

	t.Setenv("LANG", "zh_CN.UTF-8")
	if got := pickLanguage(""); got != "zh" {
		t.Errorf("a Chinese locale gave %q", got)
	}
	t.Setenv("LANG", "en_GB.UTF-8")
	if got := pickLanguage(""); got != "en" {
		t.Errorf("an English locale gave %q", got)
	}
	t.Setenv("LANG", "")
	if got := pickLanguage(""); got != "zh" {
		t.Errorf("with no locale the default should be Chinese, got %q", got)
	}
}

func TestTranslatorFallsBackToEnglish(t *testing.T) {
	tr := translator("fr")
	if got := tr("quit"); got != "Quit" {
		t.Errorf("an unknown language should fall back to English, got %q", got)
	}
	zh := translator("zh")
	if got := zh("status.up", 3, 4); got != "3/4 条隧道在线" {
		t.Errorf("formatted string = %q", got)
	}
}

func TestDefaultConfigPathIsWritableByWhoeverOpensIt(t *testing.T) {
	// This is opened by the person at the machine, so its configuration lives
	// in their own directory: it has to be able to write what it is told
	// without being elevated first.
	t.Setenv("VPN_GATEWAY_CONFIG", "")
	got := defaultConfigPath()
	if strings.HasPrefix(got, "/etc/") {
		t.Errorf("the default configuration is in a system directory: %q", got)
	}
	if !strings.Contains(got, "vpn-gateway") {
		t.Errorf("path = %q", got)
	}
}

func newTestSession(t *testing.T) *client.Session {
	t.Helper()
	dir := t.TempDir()
	return client.NewSession(filepath.Join(dir, "client.yaml"), slog.New(slog.DiscardHandler))
}

func TestMenuSaysItNeedsSettingUp(t *testing.T) {
	// Opening this for the first time has to say what to do, not show an
	// empty list of tunnels.
	v := buildView(sessionSnapshot(newTestSession(t)), translator("en"))
	if !strings.Contains(v.Status, "Not set up") {
		t.Errorf("status = %q", v.Status)
	}
	if v.Healthy {
		t.Error("an unconfigured application was shown as healthy")
	}
	if v.CanToggle {
		t.Error("connecting was offered with nothing to connect to")
	}
}

func TestMenuOffersConnectOnceABundleExists(t *testing.T) {
	s := newTestSession(t)
	if err := s.ImportBundle(testBundleJSON); err != nil {
		t.Fatal(err)
	}

	v := buildView(sessionSnapshot(s), translator("en"))
	if !strings.Contains(v.Status, "Not connected") {
		t.Errorf("status = %q", v.Status)
	}
	if !v.CanToggle || v.Action != "Connect" {
		t.Errorf("action = %q, canToggle = %t", v.Action, v.CanToggle)
	}
	if v.Healthy {
		t.Error("an idle session was shown as healthy")
	}
}

func TestMenuIsChineseByDefault(t *testing.T) {
	v := buildView(sessionSnapshot(newTestSession(t)), translator("zh"))
	if v.Status != "尚未配置" {
		t.Errorf("status = %q", v.Status)
	}
}

var testBundleJSON = []byte(`{
  "version": 1,
  "server": {"address": "vpn.example:443", "server_name": "vpn.example", "api_url": "http://vpn.example:8642"},
  "api_token": "tok",
  "tunnels": [{"name": "office", "password": "pw"}]
}`)

func TestIconsetWritesIntoAFreshDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "icons")
	if err := writeIconset(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "icon_512x512.png")); err != nil {
		t.Errorf("the iconset is incomplete: %v", err)
	}
}

func TestBothTrayLanguagesCoverTheSameKeys(t *testing.T) {
	// A key in one language and not the other shows as raw key text in the
	// menu bar, which reads as a bug rather than a translation gap.
	zh, en := trayStrings["zh"], trayStrings["en"]
	for k := range zh {
		if _, ok := en[k]; !ok {
			t.Errorf("%q is in Chinese but missing from English", k)
		}
	}
	for k := range en {
		if _, ok := zh[k]; !ok {
			t.Errorf("%q is in English but missing from Chinese; the tray defaults to Chinese", k)
		}
	}
}

func TestEveryTrayStringTheMenuAsksForExists(t *testing.T) {
	// Every key the menu uses, checked against the table rather than trusted.
	tr := translator("zh")
	for _, key := range []string{
		"title", "description", "open", "connect", "disconnect", "quit",
		"status.setup", "status.idle", "status.connecting", "status.failed", "status.up",
		"tunnel.up", "tunnel.down",
		"tip.setup", "tip.idle", "tip.connecting", "tip.failed", "tip.ok",
	} {
		if got := tr(key); got == key {
			t.Errorf("%q is missing from the table", key)
		}
	}
}

func TestAMissingStringShowsItsKey(t *testing.T) {
	// Blank menu entries look like a broken application; a visible key says
	// which string is absent.
	if got := translator("zh")("no.such.key"); got != "no.such.key" {
		t.Errorf("a missing string came back as %q", got)
	}
}

func TestTheTrayIsLeftAloneWhenNothingHasChanged(t *testing.T) {
	// Showing a change means attaching the menu again, which rebuilds it. A
	// menu rebuilt every few seconds is one that closes under the cursor of
	// whoever opened it, so the same state twice has to compare equal.
	tr := translator("en")
	snap := snapshot{
		Phase:       client.PhaseConnected,
		TunnelCount: 2,
		Tunnels: []tunnelLine{
			{Name: "a", Up: true, Wanted: true},
			{Name: "b", Up: true, Wanted: true},
		},
	}
	if frameOf(snap, tr) != frameOf(snap, tr) {
		t.Error("the same state produced two different frames; the tray would be rebuilt on every tick")
	}
}

func TestConnectingIsSomethingTheTrayIsToldAbout(t *testing.T) {
	// The failure this guards against is the one that shipped: a tray that
	// went on saying "not connected" after the client had connected, because
	// nothing noticed the difference.
	tr := translator("en")
	idle := frameOf(snapshot{Phase: client.PhaseIdle, TunnelCount: 2}, tr)
	up := frameOf(snapshot{
		Phase:       client.PhaseConnected,
		TunnelCount: 2,
		Tunnels: []tunnelLine{
			{Name: "a", Up: true, Wanted: true},
			{Name: "b", Up: true, Wanted: true},
		},
	}, tr)
	if idle == up {
		t.Fatal("connected and not connected produce the same frame")
	}
	if idle.Status == up.Status {
		t.Errorf("both states show %q", idle.Status)
	}
	if idle.Action == up.Action {
		t.Errorf("both states offer %q", idle.Action)
	}
	if !up.Healthy || idle.Healthy {
		t.Errorf("healthy = %t connected, %t idle", up.Healthy, idle.Healthy)
	}
}

func TestATunnelGoingDownIsAChangeToShow(t *testing.T) {
	// Still connected, so the phase is the same; what changed is inside it.
	tr := translator("en")
	all := frameOf(snapshot{
		Phase: client.PhaseConnected,
		Tunnels: []tunnelLine{
			{Name: "a", Up: true, Wanted: true},
			{Name: "b", Up: true, Wanted: true},
		},
	}, tr)
	one := frameOf(snapshot{
		Phase: client.PhaseConnected,
		Tunnels: []tunnelLine{
			{Name: "a", Up: true, Wanted: true},
			{Name: "b", Up: false, Wanted: true},
		},
	}, tr)
	if all == one {
		t.Error("a tunnel going down was not something the tray would notice")
	}
}

func TestATunnelNobodyAskedForIsNotATunnelThatIsDown(t *testing.T) {
	// Tunnels disabled on the server, or stopped by hand, come back as not
	// wanted. Counting them made a connected client show the degraded icon
	// and "2/6 tunnels up" forever, with nothing anybody could do about it.
	tr := translator("en")
	v := buildView(snapshot{
		Phase: client.PhaseConnected,
		Tunnels: []tunnelLine{
			{Name: "lan", Up: true, Wanted: true},
			{Name: "hk", Up: true, Wanted: true},
			{Name: "off-1", Wanted: false},
			{Name: "off-2", Wanted: false},
		},
	}, tr)

	if !v.Healthy {
		t.Errorf("every tunnel asked for is up, but the tray shows trouble: %q", v.Status)
	}
	if !strings.Contains(v.Status, "2/2") {
		t.Errorf("status = %q, want it to count the two that were asked for", v.Status)
	}
}

func TestATunnelThatWasAskedForAndIsDownStillShows(t *testing.T) {
	// The other half: ignoring what was not asked for must not end up
	// ignoring what was.
	tr := translator("en")
	v := buildView(snapshot{
		Phase: client.PhaseConnected,
		Tunnels: []tunnelLine{
			{Name: "lan", Up: true, Wanted: true},
			{Name: "hk", Up: false, Wanted: true},
			{Name: "off", Wanted: false},
		},
	}, tr)

	if v.Healthy {
		t.Error("a tunnel that was asked to dial is down and the tray calls it healthy")
	}
	if !strings.Contains(v.Status, "1/2") {
		t.Errorf("status = %q, want 1/2", v.Status)
	}
}

func TestConnectedWithNothingAskedForIsNotAFailure(t *testing.T) {
	// Connected, and every tunnel deliberately stopped. Nothing is broken.
	tr := translator("en")
	v := buildView(snapshot{
		Phase:   client.PhaseConnected,
		Tunnels: []tunnelLine{{Name: "off-1"}, {Name: "off-2"}},
	}, tr)

	if !v.Healthy {
		t.Error("nothing was asked to dial, so nothing is down, but the tray shows trouble")
	}
	if v.Status != tr("status.connected") {
		t.Errorf("status = %q, want %q", v.Status, tr("status.connected"))
	}
}
