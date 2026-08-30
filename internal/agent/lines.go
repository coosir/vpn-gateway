package agent

import (
	"io"
	"strings"
)

const (
	// maxLine bounds how much unterminated output is buffered before it is
	// emitted regardless, so a child that never writes a newline cannot grow
	// the buffer without limit.
	maxLine = 64 << 10

	// maxFragment bounds what is reported as an unterminated fragment.
	// Fragments exist to surface interactive prompts, which are short; past
	// this length the output is a stream of something else, and reporting it
	// on every read would copy a growing buffer over and over.
	maxFragment = 512
)

// scanLines reads r and calls fn for each line.
//
// It emits complete newline-terminated lines, and also emits a trailing
// fragment that has not been terminated yet. That second case is not an
// optimisation: an interactive prompt is usually written without a newline,
// because the cursor is meant to stay on the same line. A reader that waits
// for '\n' would never see "Please enter the SMS verification code: " and the
// tunnel would sit blocked forever with nothing to show for it.
//
// A fragment is re-emitted only when it has grown, so a prompt is reported
// once rather than on every read.
func scanLines(r io.Reader, fn func(line string, complete bool)) {
	buf := make([]byte, 4<<10)
	var pending strings.Builder
	lastFragment := ""

	for {
		n, err := r.Read(buf)
		if n > 0 {
			pending.Write(buf[:n])
			rest := pending.String()
			pending.Reset()

			for {
				idx := strings.IndexByte(rest, '\n')
				if idx < 0 {
					break
				}
				line := strings.TrimRight(rest[:idx], "\r")
				rest = rest[idx+1:]
				if line != "" {
					fn(line, true)
				}
				lastFragment = ""
			}

			if len(rest) > maxLine {
				fn(rest, true)
				rest = ""
				lastFragment = ""
			}
			pending.WriteString(rest)

			// Report the unterminated remainder so a prompt is visible
			// before the child writes anything else.
			if rest != "" && len(rest) <= maxFragment && rest != lastFragment {
				lastFragment = rest
				fn(rest, false)
			}
		}
		if err != nil {
			if rest := pending.String(); rest != "" && len(rest) <= maxFragment && rest != lastFragment {
				fn(rest, false)
			}
			return
		}
	}
}
