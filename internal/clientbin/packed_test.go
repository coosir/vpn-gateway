//go:build packed

package clientbin

import (
	"os"
	"testing"
)

// This runs only in a build that was given a client executable to carry, so
// the way to run it is the way that produces one:
//
//	gzip -9 -c dist/windows-amd64/vpn-gateway.exe > internal/clientbin/client.bin
//	go test -tags packed ./internal/clientbin/
func TestWhatIsCarriedComesBackWhole(t *testing.T) {
	if !Available() {
		t.Fatal("built with the packed tag and nothing was packed")
	}
	path, sum, err := Unpack(t.TempDir(), "client")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// An executable, not a truncated download or an empty placeholder.
	if info.Size() < 1<<20 {
		t.Errorf("unpacked %d bytes; that is not a client executable", info.Size())
	}
	if len(sum) != 64 {
		t.Errorf("digest = %q, want 64 hex characters", sum)
	}
}
