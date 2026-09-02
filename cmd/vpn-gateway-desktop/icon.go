//go:build desktop

package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
)

// Icons are drawn mathematically rather than shipped as raster assets.
// Both the application icon and the menu bar / tray icons use the same
// shield gateway emblem as the UI header logo, styled and scaled to Apple macOS 15 HIG.
const iconSize = 44 // drawn at 2x for retina menu bars

// Color palette for tray status indicators
var (
	colorGreen = color.NRGBA{R: 0x10, G: 0xb9, B: 0x81, A: 0xff} // Connected / Healthy (#10b981)
	colorAmber = color.NRGBA{R: 0xf5, G: 0x9e, B: 0x0b, A: 0xff} // Connecting / Partial (#f59e0b)
	colorRed   = color.NRGBA{R: 0xef, G: 0x44, B: 0x44, A: 0xff} // Failed / Error (#ef4444)
	colorSlate = color.NRGBA{R: 0x64, G: 0x74, B: 0x8b, A: 0xff} // Idle / Disconnected (#64748b)
	colorBlack = color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0xff} // Template icon mask
)

// shieldShape tests whether a point (x, y) in the standard 24x24 SVG coordinate
// space sits inside the outer shield contour and inner cutout contour.
func shieldShape(x, y float64) (outer bool, inner bool) {
	dx := math.Abs(x - 12.0)

	// Outer shield boundary
	if dx <= 8.0 && y >= 2.0+0.375*dx {
		if y <= 11.09 {
			outer = true
		} else {
			normX := dx / 8.0
			outer = y <= 11.09+10.91*math.Sqrt(math.Max(0, 1.0-normX*normX))
		}
	}

	// Inner cutout boundary
	if dx <= 6.0 && y >= 4.18+0.375*dx {
		if y <= 11.09 {
			inner = true
		} else {
			normX := dx / 6.0
			inner = y <= 11.09+8.91*math.Sqrt(math.Max(0, 1.0-normX*normX))
		}
	}
	return outer, inner
}

// drawTrayShield renders an optical 16pt (32px at 2x retina) shield icon centered in 44x44.
func drawTrayShield(fg color.NRGBA, broken bool, fillInner bool) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, iconSize, iconSize))

	for y := range iconSize {
		for x := range iconSize {
			var outerHits, innerHits int
			const samples = 4
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					px := float64(x) + (float64(sx)+0.5)/float64(samples)
					py := float64(y) + (float64(sy)+0.5)/float64(samples)

					// Standard optical height: 32px (y: 6.0 to 38.0), optical width: 26px (x: 8.5 to 34.5)
					svgX := 12.0 + (px-21.5)*(16.0/26.0)
					svgY := 2.0 + (py-6.0)*(20.0/32.0)

					o, i := shieldShape(svgX, svgY)
					if broken {
						// Open a wedge at the top right to distinguish degraded states
						dx := svgX - 12.0
						dy := svgY - 12.0
						angle := math.Atan2(-dy, dx)
						if angle > 0.35 && angle < 1.25 {
							o = false
							i = false
						}
					}
					if o {
						outerHits++
					}
					if i {
						innerHits++
					}
				}
			}

			total := float64(samples * samples)
			outerCov := float64(outerHits) / total
			innerCov := float64(innerHits) / total

			borderCov := math.Max(0, outerCov-innerCov)
			if fillInner && innerCov > 0 {
				alpha := borderCov + innerCov*0.25
				if alpha > 0 {
					img.SetNRGBA(x, y, blend(fg, clamp(alpha)))
				}
			} else if borderCov > 0 {
				img.SetNRGBA(x, y, blend(fg, clamp(borderCov)))
			}
		}
	}

	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

// connectedIcon is the template shield icon for macOS menu bar.
func connectedIcon() []byte { return drawTrayShield(colorBlack, false, false) }

// degradedIcon is the broken template shield icon for macOS menu bar.
func degradedIcon() []byte { return drawTrayShield(colorBlack, true, false) }

// statusIcon returns a colored shield icon reflecting the client lifecycle state.
func statusIcon(phase client.Phase, healthy bool) []byte {
	switch phase {
	case client.PhaseConnected:
		if healthy {
			return drawTrayShield(colorGreen, false, true)
		}
		return drawTrayShield(colorAmber, true, true)
	case client.PhaseConnecting:
		return drawTrayShield(colorAmber, false, true)
	case client.PhaseFailed:
		return drawTrayShield(colorRed, true, true)
	case client.PhaseSetup, client.PhaseIdle:
		return drawTrayShield(colorSlate, false, false)
	default:
		return drawTrayShield(colorSlate, false, false)
	}
}

// appIcon draws the launcher application icon conforming to macOS Big Sur/Sequoia HIG:
// an 82% standard inset squircle with soft bottom drop shadow and the centered shield emblem.
func appIcon(size int) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))

	s := float64(size)

	// Apple macOS 15 HIG standard icon sizing: 81.5% squircle body centered in canvas
	bodySize := s * 0.815
	bodyLeft := (s - bodySize) / 2.0
	bodyTop := s * 0.075
	corner := bodySize * 0.224

	// Rich tech-blue gradient background (#258cfb to #0e59c5)
	bgTop := color.NRGBA{R: 0x25, G: 0x8c, B: 0xfb, A: 0xff}
	bgBottom := color.NRGBA{R: 0x0e, G: 0x59, B: 0xc5, A: 0xff}

	// Shield foreground
	fgShield := color.NRGBA{R: 0xe0, G: 0xf2, B: 0xfe, A: 0xff} // crisp ice-blue/white
	fgInner := color.NRGBA{R: 0x38, G: 0xbd, B: 0xf8, A: 0x60}  // glowing tech-blue tint

	shieldPad := bodySize * 0.20
	shieldDim := bodySize - 2*shieldPad
	shieldLeft := bodyLeft + shieldPad
	shieldTop := bodyTop + shieldPad

	shadowOffset := s * 0.035
	shadowBlur := s * 0.04

	for y := range size {
		fy := float64(y)
		vRatio := (fy - bodyTop) / bodySize
		if vRatio < 0 {
			vRatio = 0
		} else if vRatio > 1 {
			vRatio = 1
		}
		bgCur := color.NRGBA{
			R: uint8(float64(bgTop.R)*(1-vRatio) + float64(bgBottom.R)*vRatio),
			G: uint8(float64(bgTop.G)*(1-vRatio) + float64(bgBottom.G)*vRatio),
			B: uint8(float64(bgTop.B)*(1-vRatio) + float64(bgBottom.B)*vRatio),
			A: 0xff,
		}

		for x := range size {
			fx := float64(x)

			// Drop shadow calculation
			sdx := math.Max(math.Max(bodyLeft+corner-fx, fx-(bodyLeft+bodySize-1-corner)), 0)
			sdy := math.Max(math.Max(bodyTop+shadowOffset+corner-fy, fy-(bodyTop+shadowOffset+bodySize-1-corner)), 0)
			sdist := math.Hypot(sdx, sdy)
			shadowAlpha := clamp(corner+shadowBlur-sdist) / shadowBlur * 0.22

			// Rounded squircle mask
			dx := math.Max(math.Max(bodyLeft+corner-fx, fx-(bodyLeft+bodySize-1-corner)), 0)
			dy := math.Max(math.Max(bodyTop+corner-fy, fy-(bodyTop+bodySize-1-corner)), 0)
			dist := math.Hypot(dx, dy)
			bgAlpha := clamp(corner + 0.5 - dist)

			// Subpixel sampling for shield inside squircle
			var outerHits, innerHits int
			const samples = 3
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					px := fx + (float64(sx)+0.5)/float64(samples)
					py := fy + (float64(sy)+0.5)/float64(samples)

					svgX := (px - shieldLeft) * (24.0 / shieldDim)
					svgY := (py - shieldTop) * (24.0 / shieldDim)

					o, i := shieldShape(svgX, svgY)
					if o {
						outerHits++
					}
					if i {
						innerHits++
					}
				}
			}

			total := float64(samples * samples)
			outerCov := float64(outerHits) / total
			innerCov := float64(innerHits) / total
			borderCov := math.Max(0, outerCov-innerCov)

			pixelColor := bgCur
			if borderCov > 0 {
				pixelColor = over(fgShield, pixelColor, borderCov)
			}
			if innerCov > 0 {
				innerAlpha := float64(fgInner.A) / 255.0 * innerCov
				pixelColor = over(fgInner, pixelColor, innerAlpha)
			}

			if bgAlpha > 0 {
				img.SetNRGBA(x, y, blend(pixelColor, bgAlpha))
			} else if shadowAlpha > 0 {
				shadowColor := color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: uint8(shadowAlpha * 255)}
				img.SetNRGBA(x, y, shadowColor)
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

// appIconICO packs the launcher icon into a multi-resolution Windows .ico file.
func appIconICO() []byte {
	sizes := []int{16, 24, 32, 48, 64, 128, 256}
	type item struct {
		size int
		data []byte
	}
	items := make([]item, len(sizes))
	for i, s := range sizes {
		items[i] = item{size: s, data: appIcon(s)}
	}

	var buf bytes.Buffer
	// ICONDIR Header
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))          // Reserved
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1))          // Type = 1 (ICO)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(items))) // Count

	offset := uint32(6 + 16*len(items))
	for _, it := range items {
		w := byte(it.size)
		if it.size >= 256 {
			w = 0
		}
		h := w
		buf.WriteByte(w)                                                   // Width
		buf.WriteByte(h)                                                   // Height
		buf.WriteByte(0)                                                   // ColorCount
		buf.WriteByte(0)                                                   // Reserved
		_ = binary.Write(&buf, binary.LittleEndian, uint16(1))             // Planes
		_ = binary.Write(&buf, binary.LittleEndian, uint16(32))            // BitCount
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(it.data)))  // BytesInRes
		_ = binary.Write(&buf, binary.LittleEndian, offset)                // ImageOffset
		offset += uint32(len(it.data))
	}

	for _, it := range items {
		buf.Write(it.data)
	}
	return buf.Bytes()
}
