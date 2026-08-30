// Package build holds checks on the repository's own build definitions.
package build

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every target named in .PHONY has to actually exist. A block edit to the
// Makefile can remove a rule and leave its name in .PHONY, and make then
// answers "Nothing to be done" rather than failing: the target is simply gone
// and nothing says so.
func TestEveryPhonyTargetHasARule(t *testing.T) {
	body := readMakefile(t)

	phony := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		rest, ok := strings.CutPrefix(line, ".PHONY:")
		if !ok {
			continue
		}
		for _, name := range strings.Fields(rest) {
			phony[name] = true
		}
	}
	if len(phony) == 0 {
		t.Fatal("no .PHONY line found; this check is not looking at the right file")
	}

	defined := definedTargets(body)
	for name := range phony {
		if !defined[name] {
			t.Errorf("%q is declared .PHONY but has no rule", name)
		}
	}
}

// The targets the documentation tells people to run have to be there.
func TestDocumentedTargetsExist(t *testing.T) {
	defined := definedTargets(readMakefile(t))
	for _, name := range []string{
		"build", "test", "check", "check-desktop",
		"dist",    // the server's binaries, cross-compiled
		"desktop", // the tray and window
		"app",     // the macOS bundle
		"images",  // built here, for trying out
		"push",    // built here, published
		"builder", // the multi-platform builder push needs
		"image-inode",
		"clean",
	} {
		if !defined[name] {
			t.Errorf("%q is documented but has no rule", name)
		}
	}
}

var targetLine = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9_%-]*)\s*:`)

func definedTargets(body string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "\t") || strings.HasPrefix(line, ".") {
			continue
		}
		if m := targetLine.FindStringSubmatch(line); m != nil {
			out[m[1]] = true
		}
	}
	// A pattern rule such as image-% also defines image-inode's siblings.
	if out["image-%"] {
		out["image-mock"], out["image-sangfor"], out["image-openconnect"] = true, true, true
	}
	if out["push-%"] {
		out["push-mock"], out["push-sangfor"], out["push-openconnect"] = true, true, true
	}
	return out
}

func readMakefile(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatalf("read the Makefile: %v", err)
	}
	return string(body)
}
