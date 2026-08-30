package agent

import (
	"io"
	"strings"
	"testing"
)

func collect(input string) []struct {
	line     string
	complete bool
} {
	var got []struct {
		line     string
		complete bool
	}
	scanLines(strings.NewReader(input), func(line string, complete bool) {
		got = append(got, struct {
			line     string
			complete bool
		}{line, complete})
	})
	return got
}

func TestScanLinesEmitsCompleteLines(t *testing.T) {
	got := collect("first\nsecond\r\nthird\n")
	want := []string{"first", "second", "third"}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].line != w || !got[i].complete {
			t.Errorf("line %d = %q complete=%t, want %q complete", i, got[i].line, got[i].complete, w)
		}
	}
}

func TestScanLinesEmitsUnterminatedPrompt(t *testing.T) {
	// This is the case that matters: an interactive prompt keeps the cursor
	// on the same line, so waiting for a newline would never surface it and
	// the tunnel would block forever with nothing to show.
	got := collect("connecting\nPlease enter your SMS code: ")
	if len(got) != 2 {
		t.Fatalf("got %d emissions, want 2: %v", len(got), got)
	}
	if got[1].line != "Please enter your SMS code: " {
		t.Errorf("fragment = %q", got[1].line)
	}
	if got[1].complete {
		t.Error("the prompt was reported as a complete line")
	}
}

// slowReader delivers its content in pieces, the way a pipe does.
type slowReader struct {
	chunks []string
	i      int
}

func (r *slowReader) Read(p []byte) (int, error) {
	if r.i >= len(r.chunks) {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[r.i])
	r.i++
	return n, nil
}

func TestScanLinesReportsAGrowingFragmentOnce(t *testing.T) {
	// A prompt arriving in pieces must be reported as it grows, but a read
	// that adds nothing must not raise the same challenge twice.
	var got []string
	scanLines(&slowReader{chunks: []string{"Please enter ", "the SMS ", "code: "}},
		func(line string, complete bool) {
			if !complete {
				got = append(got, line)
			}
		})
	if len(got) == 0 {
		t.Fatal("no fragment was reported")
	}
	last := got[len(got)-1]
	if last != "Please enter the SMS code: " {
		t.Errorf("final fragment = %q", last)
	}
	for i := 1; i < len(got); i++ {
		if got[i] == got[i-1] {
			t.Errorf("fragment %q was reported twice in a row", got[i])
		}
	}
}

func TestScanLinesFlushesAnOverlongFragment(t *testing.T) {
	// A child that never writes a newline must not be able to grow the
	// buffer without limit.
	got := collect(strings.Repeat("x", maxLine+100))
	if len(got) == 0 {
		t.Fatal("nothing was emitted")
	}
	var flushed bool
	for _, g := range got {
		if g.complete && len(g.line) > maxLine {
			flushed = true
		}
	}
	if !flushed {
		t.Errorf("the oversized buffer was never flushed as a line: %d emissions", len(got))
	}
}

func TestScanLinesDoesNotReportLongOutputAsAPrompt(t *testing.T) {
	// Fragments exist to surface short interactive prompts. Reporting a
	// growing multi-kilobyte buffer on every read would copy it over and
	// over for output that cannot be a prompt.
	var fragments int
	scanLines(strings.NewReader(strings.Repeat("y", maxLine+100)), func(line string, complete bool) {
		if !complete {
			fragments++
			if len(line) > maxFragment {
				t.Errorf("a %d byte fragment was reported as a prompt", len(line))
			}
		}
	})
}

func TestScanLinesSkipsBlankLines(t *testing.T) {
	got := collect("a\n\n\nb\n")
	if len(got) != 2 {
		t.Errorf("got %d lines, want 2: %v", len(got), got)
	}
}
