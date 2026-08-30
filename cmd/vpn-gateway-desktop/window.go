//go:build desktop

package main

import (
	webview "github.com/webview/webview_go"
)

// Window geometry. The interface is a dense table, so it wants width more
// than height, and it stays usable well below this.
const (
	windowWidth  = 1100
	windowHeight = 720
	windowMinW   = 720
	windowMinH   = 460
)

// runWindow opens a native window on the client's interface and blocks until
// it is closed. It owns this process's main run loop, which is why it runs in
// its own process rather than alongside the tray.
func runWindow(link, lang string) {
	w := webview.New(false)
	defer w.Destroy()

	w.SetTitle(translator(lang)("title"))
	w.SetSize(windowWidth, windowHeight, webview.HintNone)
	w.SetSize(windowMinW, windowMinH, webview.HintMin)
	w.Navigate(link)
	w.Run()
}
