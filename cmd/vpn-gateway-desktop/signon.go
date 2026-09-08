//go:build desktop

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/vpn-gateway/vpn-gateway/internal/client/ui"
)

// A sign-on is the one question this application answers rather than
// displays.
//
// Every other challenge is something a person can read off a screen and type:
// a code from a phone, the characters in a captcha, the address a login page
// redirected to. The page in the window collects those and sends them on.
//
// This one cannot work that way. A gateway that signs people in through an
// identity provider finishes by leaving a cookie on its own website, and says
// so in as many words -- the last page it serves reads "Please close this
// browser window." Nothing on a page served from loopback can read a cookie
// belonging to somebody else's origin, and no browser on the machine will
// hand one over either. What can read it is a webview this process opened and
// can run script in, which is exactly what the vendor's own client does and
// the only reason it needs to be a client rather than a web page.
//
// So the window is opened here, the person signs in inside it, and the moment
// the cookie appears the page is sent to a one-shot address on loopback that
// carries the value back. Nobody presses anything: arriving at the end of the
// sign-on is the whole signal, and asking for a click afterwards would only
// be a way to get it wrong.

// signOnPoll is how often the pending questions are looked at.
//
// Fast enough that a window opens while somebody is still expecting one, slow
// enough that a client sitting idle is not asking the background service for
// its state several times a second.
const signOnPoll = 1500 * time.Millisecond

// signOnWindowSize is roomy enough for an identity provider's own login page,
// which is not designed for anything small.
const (
	signOnWidth  = 520
	signOnHeight = 680
)

// signOnWatcher opens a window for each sign-on that turns up, and takes the
// answer back to whichever engine asked.
type signOnWatcher struct {
	app *application.App
	sv  *supervisor
	t   func(string, ...any) string
	log *slog.Logger

	mu sync.Mutex
	// open is the window showing each question, by prompt id.
	open map[string]*signOnWindow
	// settled is every question this application has finished with, whether
	// it carried the answer back or the person shut the window on it.
	//
	// Without it a window closed unanswered would be reopened on the next
	// sweep, because the question is still pending -- which is a window that
	// cannot be dismissed.
	settled map[string]bool
}

func newSignOnWatcher(app *application.App, sv *supervisor,
	t func(string, ...any) string, log *slog.Logger) *signOnWatcher {

	return &signOnWatcher{
		app: app, sv: sv, t: t, log: log,
		open:    map[string]*signOnWindow{},
		settled: map[string]bool{},
	}
}

// watch follows the pending questions until ctx is done.
func (w *signOnWatcher) watch(ctx context.Context) {
	ticker := time.NewTicker(signOnPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.closeAll()
			return
		case <-ticker.C:
		}
		w.sweep(ctx)
	}
}

func (w *signOnWatcher) sweep(ctx context.Context) {
	e := w.sv.engine()

	pending := map[string]ui.PromptView{}
	for _, p := range e.Prompts() {
		if p.CookieName == "" || p.URL == "" {
			// Something the page in the window is already showing.
			continue
		}
		pending[p.ID] = p
	}

	w.mu.Lock()
	// A question that is no longer pending has been answered, put aside or
	// has expired. Either way the window showing it is stale, and so is the
	// note saying this application is done with it.
	for id, win := range w.open {
		if _, still := pending[id]; !still {
			delete(w.open, id)
			go win.close()
		}
	}
	for id := range w.settled {
		if _, still := pending[id]; !still {
			delete(w.settled, id)
		}
	}
	var toOpen []ui.PromptView
	for id, p := range pending {
		if w.open[id] != nil || w.settled[id] {
			continue
		}
		toOpen = append(toOpen, p)
	}
	w.mu.Unlock()

	for _, p := range toOpen {
		win, err := w.openWindow(ctx, e, p)
		if err != nil {
			w.log.Error("could not open a sign-on window", "tunnel", p.Tunnel, "error", err)
			// Marked settled so this is not retried every second and a half.
			// The page in the main window still offers the question, which is
			// the way through when this is not available.
			w.mu.Lock()
			w.settled[p.ID] = true
			w.mu.Unlock()
			continue
		}
		w.mu.Lock()
		w.open[p.ID] = win
		w.mu.Unlock()
	}
}

// closeAll gives up the loopback addresses when this stops watching.
//
// The windows themselves are left to the application, because the only thing
// that stops the watching is the application quitting: asking it to close a
// window on the way out means waiting on a main thread that is already going,
// and the windows go with it regardless.
func (w *signOnWatcher) closeAll() {
	w.mu.Lock()
	windows := make([]*signOnWindow, 0, len(w.open))
	for id, win := range w.open {
		windows = append(windows, win)
		delete(w.open, id)
	}
	w.mu.Unlock()
	for _, win := range windows {
		win.release()
	}
}

// settle records that this application is finished with a question, so the
// next sweep does not put the window back.
func (w *signOnWatcher) settle(id string) {
	w.mu.Lock()
	w.settled[id] = true
	delete(w.open, id)
	w.mu.Unlock()
}

// signOnWindow is one sign-on being shown: the webview, and the loopback
// address the page inside it reports back to.
type signOnWindow struct {
	win      *application.WebviewWindow
	server   *http.Server
	listener net.Listener
	once     sync.Once
}

// release takes down the one-shot callback address. It is what the window
// itself asks for on the way out; closing the window is already happening by
// then, and asking for it again would only send the same event round once
// more.
func (s *signOnWindow) release() {
	s.once.Do(func() {
		if s.server == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.server.Shutdown(ctx)
	})
}

// close ends the sign-on from this side: the address goes, and so does the
// window somebody may still be looking at.
func (s *signOnWindow) close() {
	s.release()
	if s.win != nil {
		s.win.Close()
	}
}

// openWindow shows one sign-on and arranges for its answer to come back.
func (w *signOnWatcher) openWindow(ctx context.Context, e engine, p ui.PromptView) (*signOnWindow, error) {
	// Loopback, on a port nobody chose: this is a one-shot address for one
	// question, and it goes away with the window.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("could not open a local port for the sign-on: %w", err)
	}

	// A fresh path each time, so the address that carries a corporate sign-on
	// is not one anything else on the machine could have guessed and asked
	// for. It is only ever loaded by the window opened just below.
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		listener.Close()
		return nil, err
	}
	path := "/" + hex.EncodeToString(nonce)
	callback := "http://" + listener.Addr().String() + path

	sw := &signOnWindow{listener: listener}

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(rw http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("value")
		if value == "" {
			http.Error(rw, "no sign-on value", http.StatusBadRequest)
			return
		}
		// Deliberately not the request's context: it is cancelled the moment
		// this response is written, and the answer has further to travel than
		// that when a background service is the one waiting for it.
		answerCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := e.Answer(answerCtx, p.ID, value); err != nil {
			w.log.Error("could not hand the sign-on back", "tunnel", p.Tunnel, "error", err)
			writeSignOnPage(rw, w.t("signon.lost", err.Error()))
			return
		}
		w.log.Info("sign-on completed", "tunnel", p.Tunnel)
		writeSignOnPage(rw, w.t("signon.done"))

		// The question is answered; the window has nothing left to show.
		w.settle(p.ID)
		go func() {
			// A moment for the page above to reach the webview. Closing the
			// window while it is still being written leaves somebody looking
			// at a window that vanished without saying anything.
			time.Sleep(700 * time.Millisecond)
			sw.close()
		}()
	})

	sw.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := sw.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			w.log.Error("the sign-on callback stopped", "error", err)
		}
	}()

	title := w.t("signon.title", p.Tunnel)
	sw.win = w.app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:   "signon-" + p.ID,
		Title:  title,
		Width:  signOnWidth,
		Height: signOnHeight,
		Hidden: true,
		// Loaded rather than navigated to, because on Windows the injected
		// script is only installed for a window that starts from HTML. It
		// leaves immediately for the gateway's own sign-on address.
		HTML: bootstrapHTML(title, p.URL),
		JS:   captureScript(p.CookieName, callback),
	})

	sw.win.RegisterHook(events.Common.WindowClosing, func(*application.WindowEvent) {
		// Shutting the window is a decision, not a failure. The gateway is
		// still waiting and the question is still on the page in the main
		// window; what must not happen is this putting the window straight
		// back a second and a half later.
		w.settle(p.ID)
		go sw.release()
	})

	showWindow(sw.win)
	return sw, nil
}

// bootstrapHTML is the page the window starts on, which exists only to leave.
//
// The link is there for the case where neither redirect fires, so a window
// that has gone wrong is still a window somebody can get out of.
func bootstrapHTML(title, target string) string {
	safe := html.EscapeString(target)
	return `<!doctype html><html><head><meta charset="utf-8">` +
		`<title>` + html.EscapeString(title) + `</title>` +
		`<meta http-equiv="refresh" content="0;url=` + safe + `">` +
		`</head><body style="font:14px system-ui;margin:2em;color:#555">` +
		`<p><a href="` + safe + `">` + safe + `</a></p>` +
		`<script>location.replace(` + jsString(target) + `);</script>` +
		`</body></html>`
}

// captureScript is run in the window after every page it loads.
//
// It looks for one cookie by name and does nothing at all until it appears,
// which is only on the gateway's own origin and only once the sign-on has
// gone through. Identity provider pages come and go underneath it without it
// touching anything: they do not carry that cookie, and it reads nothing
// else. When the cookie does turn up the page is sent to the loopback address
// that carries the value home -- a navigation rather than a request, because a
// page on somebody else's origin is not allowed to make requests here and
// does not need to be.
func captureScript(cookieName, callback string) string {
	return `(function(){try{` +
		`if(window.__vgSignOnSent)return;` +
		`var re=new RegExp("(?:^|;\\s*)"+` + jsString(cookieName) + `+"=([^;]+)");` +
		`var m=document.cookie.match(re);` +
		`if(!m||!m[1])return;` +
		`window.__vgSignOnSent=1;` +
		`location.replace(` + jsString(callback) + `+"?value="+encodeURIComponent(m[1]));` +
		`}catch(e){}})();`
}

// jsString renders a Go string as a JavaScript literal. JSON is a subset of
// JavaScript, so encoding one is exactly this and nothing has to be escaped
// by hand.
func jsString(s string) string {
	raw, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(raw)
}

func writeSignOnPage(rw http.ResponseWriter, message string) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(rw, `<!doctype html><html><head><meta charset="utf-8"></head>`+
		`<body style="font:15px system-ui;margin:3em;color:#333;text-align:center">`+
		`<p>%s</p></body></html>`, html.EscapeString(message))
}
