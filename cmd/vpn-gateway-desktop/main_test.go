//go:build desktop

package main

import (
	"net/http"
	"net/http/httptest"
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

func TestFindLinkPrefersTheGivenLink(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	got, err := findLink("http://127.0.0.1:1/?token=t", "/nonexistent/client.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://127.0.0.1:1/?token=t" {
		t.Errorf("link = %q", got)
	}
}

func TestFindLinkUsesTheRememberedOne(t *testing.T) {
	// Opening this from a launcher passes no arguments, so a link that worked
	// once has to keep working without them.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	want := "http://127.0.0.1:9999/?token=remembered"
	if err := rememberLink(want); err != nil {
		t.Skipf("no user configuration directory here: %v", err)
	}
	got, err := findLink("", "/nonexistent/client.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("link = %q, want the remembered one", got)
	}
}

func TestRememberedLinkIsPrivate(t *testing.T) {
	// It carries a token that can drive the interface.
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	if err := rememberLink("http://127.0.0.1:1/?token=t"); err != nil {
		t.Skipf("no user configuration directory here: %v", err)
	}
	info, err := os.Stat(cachePath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("the remembered link is mode %o, want 600", perm)
	}
}

func TestFindLinkReadsTheClientsLinkFile(t *testing.T) {
	// The client usually runs elevated and keeps its token to itself; this is
	// the path that lets a desktop session find the link anyway.
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "cfg"))
	t.Setenv("HOME", dir)

	linkPath := filepath.Join(dir, "link")
	want := "http://127.0.0.1:8645/?token=from-the-client"
	if err := os.WriteFile(linkPath, []byte(want+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "client.yaml")
	body := "bundle: /dev/null\nproxy: {enabled: true}\n" +
		"ui: {enabled: true, listen: \"127.0.0.1:8645\", state_dir: " + dir + "/unreadable, link_file: " + linkPath + "}\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := findLink("", cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("link = %q", got)
	}
}

func TestFindLinkExplainsWhatToDoWithNothingToGoOn(t *testing.T) {
	// This is what a launcher sees on a fresh machine, and it has to say
	// something a person can act on rather than exiting silently.
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)

	_, err := findLink("", filepath.Join(dir, "absent.yaml"))
	if err == nil {
		t.Fatal("a missing configuration was accepted")
	}
	for _, want := range []string{"-url", "remembered"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message does not mention %q:\n%v", want, err)
		}
	}
}

func TestFindLinkNoticesTheInterfaceIsOff(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)

	cfgPath := filepath.Join(dir, "client.yaml")
	if err := os.WriteFile(cfgPath, []byte("bundle: /dev/null\nproxy: {enabled: true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := findLink("", cfgPath)
	if err == nil || !strings.Contains(err.Error(), "ui.enabled") {
		t.Errorf("a client with no interface should say so, got %v", err)
	}
}

func TestCheckLinkRejectsAWrongToken(t *testing.T) {
	// A mistyped link must fail now, with a reason, rather than being
	// remembered and failing silently on every later launch.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer right" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"tunnels":[]}`))
	}))
	defer srv.Close()

	if err := checkLink(srv.URL + "/?token=right"); err != nil {
		t.Errorf("a working link was rejected: %v", err)
	}

	err := checkLink(srv.URL + "/?token=wrong")
	if err == nil {
		t.Fatal("a wrong token was accepted")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("the message does not explain: %v", err)
	}
}

func TestCheckLinkReportsAClientThatIsNotRunning(t *testing.T) {
	err := checkLink("http://127.0.0.1:9/?token=t")
	if err == nil {
		t.Fatal("an unreachable client was accepted")
	}
	if !strings.Contains(err.Error(), "running") {
		t.Errorf("the message does not say what is wrong: %v", err)
	}
}
