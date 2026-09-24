// Package alert tells someone when a tunnel has gone offline and is not
// coming back by itself.
//
// Two things count. A manual tunnel whose session ended is down until a person
// dials it again, so that is reported the moment it happens. Any other tunnel
// that should be up redials on its own, and most drops are over before anyone
// could read about them; only one still not up after a grace period -- its
// agent gave up, the gateway wants a code, the container will not start -- is
// reported. A tunnel somebody stopped is not offline, it is off.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server/tunnel"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// Notifier delivers one alert.
type Notifier interface {
	Notify(ctx context.Context, title, body string) error
}

// Source is what the watcher reads tunnels from; *tunnel.Manager is one.
type Source interface {
	Subscribe() (<-chan tunnel.Event, func())
	Snapshots() []tunnel.Snapshot
}

// Bark pushes alerts through a Bark server (https://github.com/Finb/Bark).
type Bark struct {
	// URL is the device endpoint, e.g. https://api.day.app/<key>. Its query
	// string, if any, is kept.
	URL    string
	Client *http.Client
}

// Notify posts one push. The JSON body is what Bark's v2 API takes, and it
// leaves the title and body out of the path, where any slash in a tunnel's
// last error would have broken the URL.
func (b Bark) Notify(ctx context.Context, title, body string) error {
	payload, err := json.Marshal(map[string]string{
		"title": title,
		"body":  body,
		"group": "vpn-gateway",
		// Offline is worth breaking through a focus mode for.
		"level": "timeSensitive",
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	client := b.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("bark answered %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

const (
	// checkInterval is how often a tunnel's time offline is measured against
	// the grace period. Events arrive only on change, and a tunnel stuck
	// dialling changes nothing.
	checkInterval = 15 * time.Second

	sendAttempts = 3
	sendRetry    = 10 * time.Second
)

// Options configures a Watcher.
type Options struct {
	Notifier Notifier
	// Grace is how long a tunnel that should be up may stay down before that
	// is reported.
	Grace time.Duration
	// Label names this server in every alert.
	Label string
	// Manual lists the tunnels that only a person dials.
	Manual map[string]bool
	Log    *slog.Logger
}

// Watcher turns tunnel events into alerts.
type Watcher struct {
	opts  Options
	now   func() time.Time
	send  chan message
	state map[string]*watch
}

type watch struct {
	snap tunnel.Snapshot
	// downSince is when a tunnel that should be up was last seen not up;
	// zero while it is up or nobody wants it.
	downSince time.Time
	// alerted is whether an offline alert went out that no recovery has
	// answered yet, so one outage is one alert.
	alerted bool
}

type message struct{ title, body string }

// New builds a watcher.
func New(opts Options) *Watcher {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Watcher{
		opts:  opts,
		now:   time.Now,
		send:  make(chan message, 64),
		state: map[string]*watch{},
	}
}

// Run watches src until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context, src Source) {
	events, release := src.Subscribe()
	defer release()

	go w.deliver(ctx)

	for _, s := range src.Snapshots() {
		w.observe(tunnel.Event{At: w.now(), Tunnel: s})
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			w.observe(ev)
		case <-ticker.C:
			w.check()
		}
	}
}

// observe folds one event into what is known about its tunnel.
func (w *Watcher) observe(ev tunnel.Event) {
	s := ev.Tunnel
	if s.Disabled {
		return
	}
	st := w.state[s.Name]
	if st == nil {
		st = &watch{}
		w.state[s.Name] = st
	}
	st.snap = s
	at := ev.At
	if at.IsZero() {
		at = w.now()
	}

	switch {
	case ev.StoodDown:
		// A manual tunnel's session ended and nothing will redial it.
		st.downSince = time.Time{}
		if !st.alerted {
			st.alerted = true
			w.enqueue(fmt.Sprintf("%s 离线", s.Name),
				withReason("会话已断开，手动隧道不会自动重连，需要有人重新连接。", s.LastError))
		}

	case !s.Wanted:
		// Stopped by somebody, or never asked for. An alert already sent
		// stays open, so the tunnel coming back still says so.
		st.downSince = time.Time{}

	case s.Status.State == contract.StateUp && s.Reachable:
		st.downSince = time.Time{}
		if st.alerted {
			st.alerted = false
			w.enqueue(fmt.Sprintf("%s 已恢复", s.Name), "隧道重新连上了。")
		}

	default:
		if st.downSince.IsZero() {
			st.downSince = at
		}
	}
}

// check reports tunnels that have been down past the grace period.
func (w *Watcher) check() {
	now := w.now()
	names := make([]string, 0, len(w.state))
	for name := range w.state {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		st := w.state[name]
		if st.alerted || st.downSince.IsZero() {
			continue
		}
		// A manual tunnel coming up has a person dialling it, answering the
		// gateway's questions; the moment it fails it stands down, and that
		// is reported on its own.
		if w.opts.Manual[name] {
			continue
		}
		down := now.Sub(st.downSince)
		if down < w.opts.Grace {
			continue
		}
		st.alerted = true
		w.enqueue(fmt.Sprintf("%s 离线", name),
			withReason(fmt.Sprintf("自动重连 %s 仍未成功（当前状态：%s）。", roundDuration(down), describe(st.snap)),
				st.snap.LastError))
	}
}

func describe(s tunnel.Snapshot) string {
	if !s.Reachable && s.Status.State != contract.StateError {
		return "容器无响应"
	}
	switch s.Status.State {
	case contract.StateConnecting:
		return "连接中"
	case contract.StateAuthRequired:
		return "等待验证码"
	case contract.StateDown:
		return "已断开"
	case contract.StateError:
		return "出错"
	default:
		return string(s.Status.State)
	}
}

func withReason(body, reason string) string {
	if reason = strings.TrimSpace(reason); reason != "" {
		return body + "\n原因：" + reason
	}
	return body
}

func roundDuration(d time.Duration) time.Duration {
	if d >= time.Minute {
		return d.Round(time.Minute)
	}
	return d.Round(time.Second)
}

func (w *Watcher) enqueue(title, body string) {
	if w.opts.Label != "" {
		title = "[" + w.opts.Label + "] " + title
	}
	w.opts.Log.Warn("tunnel alert", "title", title, "body", body)
	select {
	case w.send <- message{title, body}:
	default:
		w.opts.Log.Warn("alert queue full, dropping", "title", title)
	}
}

// deliver sends queued alerts one at a time, so a slow push service holds up
// alerts and never the event stream.
func (w *Watcher) deliver(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-w.send:
			var err error
			for attempt := range sendAttempts {
				if attempt > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(sendRetry):
					}
				}
				if err = w.opts.Notifier.Notify(ctx, m.title, m.body); err == nil {
					break
				}
			}
			if err != nil {
				w.opts.Log.Warn("sending an alert failed", "title", m.title, "error", err)
			}
		}
	}
}
