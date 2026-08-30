//go:build desktop

package main

import (
	"bytes"
	"image"
	"image/png"
	"os"
	"testing"
)

func decode(t *testing.T, raw []byte) image.Image {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("the icon is not a valid PNG: %v", err)
	}
	return img
}

func TestIconsAreValidAndDistinct(t *testing.T) {
	connected := connectedIcon()
	degraded := degradedIcon()

	for name, raw := range map[string][]byte{"connected": connected, "degraded": degraded} {
		img := decode(t, raw)
		b := img.Bounds()
		if b.Dx() != iconSize || b.Dy() != iconSize {
			t.Errorf("%s icon is %dx%d, want %d square", name, b.Dx(), b.Dy(), iconSize)
		}
	}

	// The two states are told apart by shape, because a template icon is
	// tinted by the system and any colour would be discarded.
	if bytes.Equal(connected, degraded) {
		t.Fatal("both states produce the same icon")
	}
	if opaque(t, connected) <= opaque(t, degraded) {
		t.Error("the broken ring is not missing a wedge; the two states would look alike")
	}
}

func TestIconIsATemplate(t *testing.T) {
	// macOS tints a template icon itself, so it must carry shape in alpha and
	// no colour of its own.
	img := decode(t, connectedIcon())
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, a := img.At(x, y).RGBA()
			if a == 0 {
				continue
			}
			if r != 0 || g != 0 || bl != 0 {
				t.Fatalf("pixel at %d,%d carries colour (%d,%d,%d); a template icon must be black", x, y, r, g, bl)
			}
		}
	}
}

func TestIconHasAHole(t *testing.T) {
	// A filled disc reads as a blob at menu bar size. The middle has to be
	// clear for it to read as a ring.
	img := decode(t, connectedIcon())
	mid := iconSize / 2
	if _, _, _, a := img.At(mid, mid).RGBA(); a != 0 {
		t.Error("the centre is filled; the icon would read as a disc rather than a ring")
	}
	// And the ring itself has to be there.
	if _, _, _, a := img.At(mid, 4).RGBA(); a == 0 {
		t.Error("the ring is missing at the top")
	}
}

func opaque(t *testing.T, raw []byte) int {
	t.Helper()
	img := decode(t, raw)
	b := img.Bounds()
	n := 0
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if _, _, _, a := img.At(x, y).RGBA(); a > 0x8000 {
				n++
			}
		}
	}
	return n
}

// TestWriteIconsForInspection saves the icons when asked, so they can be
// looked at rather than only measured.
func TestWriteIconsForInspection(t *testing.T) {
	dir := os.Getenv("VG_ICON_OUT")
	if dir == "" {
		t.Skip("set VG_ICON_OUT to save the icons")
	}
	for name, raw := range map[string][]byte{"connected": connectedIcon(), "degraded": degradedIcon()} {
		if err := os.WriteFile(dir+"/"+name+".png", raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
