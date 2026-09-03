// Package clientbin carries the headless client executable inside the
// application, so one file is all anybody has to download.
//
// The background service must not be the application. It runs as SYSTEM or
// root, and the application is a window: half of what would be running with
// those privileges is a webview nothing ever opens, and a service built from
// the application needs a second copy of the client's own run loop to be
// something a service manager can start -- two implementations of one thing,
// which is how the two of them come to disagree.
//
// So the service runs the client executable, and on Windows, where there is no
// bundle to put a second file in, the application carries that executable and
// writes it out when the service is installed. Everywhere else it is already
// beside the application and this is not used.
package clientbin

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ErrNotPacked is returned when this build carries no client executable. It
// is not a failure of the build: only the packaged Windows application needs
// one, and every other build finds the executable beside itself.
var ErrNotPacked = errors.New("this build carries no client executable")

// Available reports whether there is an executable to write out.
func Available() bool { return len(packed) > 0 }

// Unpack writes the client executable into dir and returns where it went and
// the hex SHA-256 of what was written.
//
// The digest is returned rather than kept to itself because whoever installs
// this hands the path to an elevated process, and a path is not a file: the
// digest is how that process can tell it is copying what was written here and
// not what something else put there afterwards.
func Unpack(dir, name string) (path, sum string, err error) {
	if !Available() {
		return "", "", ErrNotPacked
	}
	return unpack(packed, dir, name)
}

func unpack(compressed []byte, dir, name string) (path, sum string, err error) {
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return "", "", fmt.Errorf("clientbin: %w", err)
	}
	defer zr.Close()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("clientbin: prepare %s: %w", dir, err)
	}
	path = filepath.Join(dir, name)
	// Truncating rather than replacing: the directory is the caller's own,
	// and a file it already owns is one it is allowed to overwrite.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		return "", "", fmt.Errorf("clientbin: write %s: %w", path, err)
	}
	digest := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, digest), zr); err != nil {
		f.Close()
		os.Remove(path)
		return "", "", fmt.Errorf("clientbin: write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", "", fmt.Errorf("clientbin: write %s: %w", path, err)
	}
	return path, hex.EncodeToString(digest.Sum(nil)), nil
}
