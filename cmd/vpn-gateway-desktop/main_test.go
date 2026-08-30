//go:build desktop

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitLinkSeparatesTheToken(t *testing.T) {
	// The token travels in a header rather than in every request line, so it
	// does not end up in any log the client keeps.
	base, token, err := splitLink("http://127.0.0.1:8645/?token=abc123")
	if err != nil {
		t.Fatal(err)
	}
	if base != "http://127.0.0.1:8645" {
		t.Errorf("base = %q", base)
	}
	if token != "abc123" {
		t.Errorf("token = %q", token)
	}
	if strings.Contains(base, "token") {
		t.Error("the token is still in the address")
	}
}

func TestSplitLinkRejectsALinkWithNoToken(t *testing.T) {
	// Without one nothing would authenticate, and the tray would sit showing
	// "client not running" against a client that is running fine.
	if _, _, err := splitLink("http://127.0.0.1:8645/"); err == nil {
		t.Fatal("a link with no token was accepted")
	}
}

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

func TestResolveLinkPrefersTheGivenLink(t *testing.T) {
	got, err := resolveLink("http://127.0.0.1:1/?token=t", "/nonexistent/client.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://127.0.0.1:1/?token=t" {
		t.Errorf("link = %q", got)
	}
}

func TestResolveLinkExplainsAnUnreadableToken(t *testing.T) {
	// The client usually runs elevated, so its state directory is often
	// unreadable to whoever is looking at the tray. A bare permission error
	// would send someone hunting in the wrong place.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client.yaml")
	body := "bundle: /dev/null\nproxy: {enabled: true}\n" +
		"ui: {enabled: true, listen: \"127.0.0.1:8645\", state_dir: " + dir + "/missing}\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := resolveLink("", cfgPath)
	if err == nil {
		t.Fatal("a missing token was accepted")
	}
	if !strings.Contains(err.Error(), "-url") {
		t.Errorf("the error does not say what to do instead:\n%v", err)
	}
}

func TestResolveLinkNoticesTheInterfaceIsOff(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client.yaml")
	if err := os.WriteFile(cfgPath, []byte("bundle: /dev/null\nproxy: {enabled: true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := resolveLink("", cfgPath)
	if err == nil || !strings.Contains(err.Error(), "ui.enabled") {
		t.Errorf("a client with no interface should say so, got %v", err)
	}
}

func promptFor(names ...string) []struct {
	Tunnel string `json:"tunnel"`
} {
	out := make([]struct {
		Tunnel string `json:"tunnel"`
	}, 0, len(names))
	for _, n := range names {
		out = append(out, struct {
			Tunnel string `json:"tunnel"`
		}{n})
	}
	return out
}

func TestATunnelWaitingForACodeIsNotHealthy(t *testing.T) {
	// This is the whole point of the icon. A tunnel blocked on a verification
	// code is not carrying traffic, and if the menu bar looks fine then the
	// one moment someone needs to notice is the one moment nothing tells
	// them.
	tr := translator("en")

	healthy := buildView(&trayState{
		Tunnels: []tunnelView{{Name: "office", Up: true}},
	}, tr)
	if !healthy.Healthy {
		t.Error("a single tunnel that is up should be healthy")
	}

	blocked := buildView(&trayState{
		Tunnels: []tunnelView{{Name: "office", Up: true}},
		Prompts: promptFor("office"),
	}, tr)
	if blocked.Healthy {
		t.Error("a tunnel waiting for a code was shown as healthy")
	}
	if !strings.Contains(blocked.Lines[0], "waiting for a code") {
		t.Errorf("the menu line does not say why: %q", blocked.Lines[0])
	}
}

func TestOneTunnelDownIsNotHealthy(t *testing.T) {
	v := buildView(&trayState{
		Tunnels: []tunnelView{{Name: "office", Up: true}, {Name: "lab", Up: false}},
	}, translator("en"))
	if v.Healthy {
		t.Error("one tunnel down should not read as healthy")
	}
	if v.Up != 1 || v.Total != 2 {
		t.Errorf("counted %d/%d", v.Up, v.Total)
	}
}

func TestNoTunnelsIsNotHealthy(t *testing.T) {
	// Nothing configured is not the same as everything working.
	v := buildView(&trayState{}, translator("en"))
	if v.Healthy {
		t.Error("a client with no tunnels was shown as healthy")
	}
	if !strings.Contains(v.Status, "No tunnels") {
		t.Errorf("status = %q", v.Status)
	}
}

func TestMenuLinesAreSorted(t *testing.T) {
	// The menu is read at a glance, so the order has to be stable rather than
	// whatever the client happened to serialise.
	v := buildView(&trayState{
		Tunnels: []tunnelView{{Name: "zulu", Up: true}, {Name: "alpha", Up: true}},
	}, translator("en"))
	if len(v.Lines) != 2 || !strings.HasPrefix(v.Lines[0], "alpha") {
		t.Errorf("lines = %v", v.Lines)
	}
}

func TestChineseMenuLines(t *testing.T) {
	v := buildView(&trayState{
		Tunnels: []tunnelView{{Name: "office", Up: true}, {Name: "corp", Up: false}},
		Prompts: promptFor("corp"),
	}, translator("zh"))
	if v.Status != "1/2 条隧道在线" {
		t.Errorf("status = %q", v.Status)
	}
	if !strings.Contains(v.Lines[0], "需要验证码") {
		t.Errorf("lines = %v", v.Lines)
	}
}
