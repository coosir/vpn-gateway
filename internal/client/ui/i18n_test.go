package ui

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// page returns the embedded interface.
func page(t *testing.T) string {
	t.Helper()
	b, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var (
	// Any quoted key whose value is a quoted string. Restricting the search
	// to one language's section keeps this from matching anything else.
	keyInDict = regexp.MustCompile(`"([A-Za-z][A-Za-z0-9_.]*)":\s*"`)
	keyInUse  = regexp.MustCompile(`\bt\("([^"]+)"`)
	keyInAttr = regexp.MustCompile(`data-i18n(?:-title)?="([^"]+)"`)
)

// section returns the body of one language's table.
func section(t *testing.T, src, lang string) string {
	t.Helper()
	start := strings.Index(src, "  "+lang+": {")
	if start < 0 {
		t.Fatalf("no %q section in the dictionary", lang)
	}
	end := strings.Index(src[start:], "\n  },")
	if end < 0 {
		t.Fatalf("the %q section is not closed", lang)
	}
	return src[start : start+end]
}

func keysOf(t *testing.T, src, lang string) map[string]bool {
	out := map[string]bool{}
	for _, m := range keyInDict.FindAllStringSubmatch(section(t, src, lang), -1) {
		out[m[1]] = true
	}
	return out
}

func TestBothLanguagesCoverTheSameKeys(t *testing.T) {
	// A key present in one language and not the other shows as raw key text
	// in the interface, which looks like a bug rather than a translation gap.
	src := page(t)
	zh := keysOf(t, src, "zh")
	en := keysOf(t, src, "en")

	if len(zh) == 0 || len(en) == 0 {
		t.Fatalf("parsed %d Chinese and %d English keys; the dictionary shape changed", len(zh), len(en))
	}
	for k := range zh {
		if !en[k] {
			t.Errorf("%q is translated into Chinese but missing from English", k)
		}
	}
	for k := range en {
		if !zh[k] {
			t.Errorf("%q is in English but missing from Chinese; the interface defaults to Chinese", k)
		}
	}
}

func TestEveryKeyUsedIsTranslated(t *testing.T) {
	src := page(t)
	zh := keysOf(t, src, "zh")

	used := map[string]bool{}
	for _, m := range keyInUse.FindAllStringSubmatch(src, -1) {
		used[m[1]] = true
	}
	for _, m := range keyInAttr.FindAllStringSubmatch(src, -1) {
		used[m[1]] = true
	}
	if len(used) == 0 {
		t.Fatal("found no translated strings at all")
	}

	for k := range used {
		// Keys built at runtime from a challenge type, such as "k."+type+".t".
		if strings.HasSuffix(k, ".") || strings.HasPrefix(k, "k.") {
			continue
		}
		if !zh[k] {
			t.Errorf("the interface asks for %q, which is not in the dictionary", k)
		}
	}
}

func TestEveryChallengeKindIsTranslated(t *testing.T) {
	// These are looked up by challenge type, so a missing one only shows when
	// a gateway actually raises that kind.
	src := page(t)
	for _, lang := range []string{"zh", "en"} {
		body := section(t, src, lang)
		for _, kind := range []string{"sms", "totp", "captcha", "url", "password", "vnc"} {
			for _, suffix := range []string{".t", ".w"} {
				key := `"k.` + kind + suffix + `":`
				if !strings.Contains(body, key) {
					t.Errorf("%s is missing %s", lang, key)
				}
			}
		}
	}
}

func TestChineseIsTheDefault(t *testing.T) {
	src := page(t)
	if !strings.Contains(src, `localStorage.getItem("vg.lang") || "zh"`) {
		t.Error("the default language is not Chinese")
	}
}

func TestRuleTargetValuesAreNotTranslated(t *testing.T) {
	// "direct" and "block" are values the client parses. Translating the
	// value rather than the label would write a Chinese word into the
	// configuration file and the rule would stop matching anything.
	src := page(t)
	if !strings.Contains(src, "o.value = name;") {
		t.Error("the rule target option no longer carries the untranslated name as its value")
	}
	if !strings.Contains(src, `const label = name === "direct" ? t("t.direct")`) {
		t.Error("the rule target label is not translated separately from its value")
	}
}

func TestPageStillHasNoExternalRequests(t *testing.T) {
	src := page(t)
	for _, forbidden := range []string{"https://fonts.", "cdn.", "unpkg", "jsdelivr"} {
		if strings.Contains(src, forbidden) {
			t.Errorf("the page reaches out to %q", forbidden)
		}
	}
}

func TestPageIsEmbeddedNotReadFromDisk(t *testing.T) {
	// The client is a single binary; a page read from the filesystem would
	// vanish the moment it was installed somewhere else.
	if _, err := os.Stat("assets/index.html"); err != nil {
		t.Skip("running outside the source tree")
	}
	if len(page(t)) < 1000 {
		t.Error("the embedded page is suspiciously small")
	}
}
