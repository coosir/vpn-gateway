//go:build desktop

package main

import (
	"bytes"
	"image"
	"image/png"
	"os"
	"runtime"
	"testing"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
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
	connected := templateIcon(client.PhaseConnected, true)
	degraded := templateIcon(client.PhaseConnected, false)

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
		t.Error("the broken shield is not missing a wedge; the two states would look alike")
	}
}

func TestIconIsATemplate(t *testing.T) {
	// macOS tints a template icon itself, so it must carry shape in alpha and
	// no colour of its own.
	img := decode(t, templateIcon(client.PhaseConnected, true))
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

func TestConnectedIsFilledAndDisconnectedIsNot(t *testing.T) {
	// The menu bar throws the colour away, so this is the whole signal: a
	// solid shield is carrying traffic and an outline is not. When both were
	// outlines, a connected client looked exactly like a stopped one.
	connected := decode(t, templateIcon(client.PhaseConnected, true))
	idle := decode(t, templateIcon(client.PhaseIdle, false))
	mid := iconSize / 2

	if _, _, _, a := connected.At(mid, mid).RGBA(); a < 0xf000 {
		t.Error("the connected icon is hollow in the middle; it reads as not connected")
	}
	if _, _, _, a := idle.At(mid, mid).RGBA(); a != 0 {
		t.Error("the idle icon is filled in; it reads as connected")
	}
	// The outline itself is there in both.
	for name, img := range map[string]image.Image{"connected": connected, "idle": idle} {
		if _, _, _, a := img.At(mid, 7).RGBA(); a == 0 {
			t.Errorf("the %s icon has no shield outline at the top", name)
		}
	}
}

func TestTheMenuBarNeverGetsAColourItWouldDiscard(t *testing.T) {
	// Asking for a template on macOS and a colour icon anywhere else is not a
	// preference: a tray that has been given a template once draws everything
	// afterwards as a stencil, so the two must never be mixed.
	icon, template := trayIcon(client.PhaseConnected, true)
	if template != (runtime.GOOS == "darwin") {
		t.Errorf("trayIcon returned template=%t on %s", template, runtime.GOOS)
	}
	if len(icon) == 0 {
		t.Error("trayIcon returned nothing to draw")
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

func TestAppIconIsOpaqueAndSquare(t *testing.T) {
	// A launcher icon is looked at rather than glanced past, so unlike the
	// menu bar one it is filled in and carries its own colour.
	img := decode(t, appIcon(256))
	if img.Bounds().Dx() != 256 || img.Bounds().Dy() != 256 {
		t.Fatalf("app icon is %v", img.Bounds())
	}
	// Inside the squircle body, it must be solid.
	if _, _, _, a := img.At(128, 28).RGBA(); a < 0xf000 {
		t.Error("the icon's ground is not opaque")
	}
	// A corner is outside it, so it must be clear.
	if _, _, _, a := img.At(1, 1).RGBA(); a != 0 {
		t.Error("the corners are not rounded")
	}
	// And the mark has colour, unlike the template icon.
	r, g, b, _ := img.At(128, 60).RGBA()
	if r == g && g == b {
		t.Error("the mark is grey; the launcher icon should carry the accent colour")
	}
}

func TestIconsetCoversWhatMacOSAsksFor(t *testing.T) {
	dir := t.TempDir()
	if err := writeIconset(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"icon_16x16.png", "icon_16x16@2x.png", "icon_32x32.png",
		"icon_128x128.png", "icon_256x256.png", "icon_512x512.png",
		"icon_512x512@2x.png",
	} {
		if _, err := os.Stat(dir + "/" + name); err != nil {
			t.Errorf("%s is missing from the iconset", name)
		}
	}
}

// TestWriteIconsForInspection saves the icons when asked, so they can be
// looked at rather than only measured.
func TestWriteIconsForInspection(t *testing.T) {
	dir := os.Getenv("VG_ICON_OUT")
	if dir == "" {
		t.Skip("set VG_ICON_OUT to save the icons")
	}
	icons := map[string][]byte{
		"connected":        templateIcon(client.PhaseConnected, true),
		"degraded":         templateIcon(client.PhaseConnected, false),
		"connecting":       templateIcon(client.PhaseConnecting, false),
		"idle":             templateIcon(client.PhaseIdle, false),
		"colour-connected": statusIcon(client.PhaseConnected, true),
		"colour-idle":      statusIcon(client.PhaseIdle, false),
	}
	for name, raw := range icons {
		if err := os.WriteFile(dir+"/"+name+".png", raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
