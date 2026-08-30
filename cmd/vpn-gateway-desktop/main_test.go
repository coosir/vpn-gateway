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
	v := buildView(newTestSession(t), translator("en"))
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

	v := buildView(s, translator("en"))
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
	v := buildView(newTestSession(t), translator("zh"))
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
