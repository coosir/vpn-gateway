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

// appIcon draws the launcher icon: the same ring, but filled in and on a
// rounded ground, because a Dock or Finder icon is looked at rather than
// glanced past and a bare outline reads as unfinished there.
func appIcon(size int) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))

	s := float64(size)
	centre := (s - 1) / 2
	corner := s * 0.22
	outer := s * 0.30
	inner := s * 0.185

	ground := color.NRGBA{R: 0x14, G: 0x17, B: 0x1c, A: 0xff}
	mark := color.NRGBA{R: 0x45, G: 0xc9, B: 0xa3, A: 0xff}

	for y := range size {
		for x := range size {
			fx, fy := float64(x), float64(y)

			// A rounded square, measured by distance to the inset rectangle.
			dx := math.Max(math.Max(corner-fx, fx-(s-1-corner)), 0)
			dy := math.Max(math.Max(corner-fy, fy-(s-1-corner)), 0)
			if math.Hypot(dx, dy) > corner+0.5 {
				continue
			}
			img.SetNRGBA(x, y, blend(ground, clamp(corner+0.5-math.Hypot(dx, dy))))

			d := math.Hypot(fx-centre, fy-centre)
			a := clamp(outer-d+0.5) * clamp(d-inner+0.5)
			if a > 0 {
				img.SetNRGBA(x, y, over(mark, ground, a))
			}
		}
	}

	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

func blend(c color.NRGBA, a float64) color.NRGBA {
	c.A = uint8(float64(c.A) * a)
	return c
}

func over(fg, bg color.NRGBA, a float64) color.NRGBA {
	mix := func(f, b uint8) uint8 { return uint8(float64(f)*a + float64(b)*(1-a)) }
	return color.NRGBA{R: mix(fg.R, bg.R), G: mix(fg.G, bg.G), B: mix(fg.B, bg.B), A: 0xff}
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
