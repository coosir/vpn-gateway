//go:build desktop

package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Icons are drawn rather than shipped as files. A menu bar icon is a ring at
// 22 pixels and nothing more, and generating it keeps the two states exactly
// consistent with each other.
//
// macOS tints a template icon itself, so these carry shape in the alpha
// channel and no colour of their own. That is also why the two states differ
// by shape: on a template icon, colour would be thrown away.
const iconSize = 44 // drawn at 2x for retina menu bars

// connectedIcon is a closed ring: every tunnel is carrying traffic.
func connectedIcon() []byte { return ring(false) }

// degradedIcon is a broken ring: at least one tunnel is not up, or the client
// cannot be reached at all.
func degradedIcon() []byte { return ring(true) }

func ring(broken bool) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, iconSize, iconSize))

	const (
		outer     = iconSize/2 - 3
		thickness = 5.0
	)
	centre := float64(iconSize-1) / 2
	inner := outer - thickness

	for y := range iconSize {
		for x := range iconSize {
			dx := float64(x) - centre
			dy := float64(y) - centre
			d := math.Hypot(dx, dy)

			// Antialias the two edges of the ring by how far the pixel sits
			// across each boundary.
			a := clamp(float64(outer)-d+0.5) * clamp(d-float64(inner)+0.5)
			if broken {
				// A wedge open at the top right, which reads as a gap even at
				// the size a menu bar draws this.
				angle := math.Atan2(-dy, dx)
				if angle > 0.35 && angle < 1.25 {
					a = 0
				}
			}
			if a <= 0 {
				continue
			}
			img.SetNRGBA(x, y, color.NRGBA{R: 0, G: 0, B: 0, A: uint8(a * 255)})
		}
	}

	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
