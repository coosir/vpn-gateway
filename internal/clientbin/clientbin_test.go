package clientbin

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestABuildWithNothingPackedSaysSoRatherThanWritingAnEmptyFile(t *testing.T) {
	// Only the packaged Windows application carries an executable. Every
	// other build finds one beside itself, and must not be handed a
	// zero-length file to install as a service.
	if Available() {
		t.Skip("this build carries a client executable")
	}
	if _, _, err := Unpack(t.TempDir(), "vpn-gateway.exe"); !errors.Is(err, ErrNotPacked) {
		t.Errorf("unpacking a build with nothing packed returned %v, want ErrNotPacked", err)
	}
}

func TestUnpackingWritesTheExecutableAndTheDigestOfWhatItWrote(t *testing.T) {
	// The digest is what an elevated process checks before copying the file
	// into a directory only root can write, so it has to describe the bytes
	// that actually landed on disk.
	want := []byte("not really an executable, but it is bytes\x00\x01\x02")
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "made", "on", "the", "way")
	path, sum, err := unpack(buf.Bytes(), dir, "vpn-gateway.exe")
	if err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("wrote %q, want %q", got, want)
	}
	digest := sha256.Sum256(want)
	if sum != hex.EncodeToString(digest[:]) {
		t.Errorf("digest = %q, want %q", sum, hex.EncodeToString(digest[:]))
	}
	if filepath.Dir(path) != dir {
		t.Errorf("wrote to %q, want it in %q", path, dir)
	}
}

func TestUnpackingTwiceOverwritesRatherThanFailing(t *testing.T) {
	// An install that was cancelled leaves the file behind, and the next one
	// must not be blocked by it.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte("second"))
	zw.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vpn-gateway.exe"), []byte("first, and longer"), 0o700); err != nil {
		t.Fatal(err)
	}
	path, _, err := unpack(buf.Bytes(), dir, "vpn-gateway.exe")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Errorf("the second unpack left %q behind", got)
	}
}

func TestCorruptedContentLeavesNoFileBehind(t *testing.T) {
	// A half-written executable is worse than none: it is a file an install
	// would happily copy into place.
	dir := t.TempDir()
	if _, _, err := unpack([]byte("this is not gzip"), dir, "vpn-gateway.exe"); err == nil {
		t.Fatal("unpacking rubbish succeeded")
	}
	if _, err := os.Stat(filepath.Join(dir, "vpn-gateway.exe")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a file was left behind: %v", err)
	}
}
