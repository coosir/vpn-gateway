package ui

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
)

// openStream subscribes the way the page does and returns each state it is
// sent.
func openStream(t *testing.T, base string) (<-chan State, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/events?token=tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("the stream answered %s", resp.Status)
	}

	out := make(chan State, 16)
	go func() {
		defer close(out)
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 4<<10), 1<<20)
		for sc.Scan() {
			raw, ok := strings.CutPrefix(sc.Text(), "data:")
			if !ok {
				continue
			}
			var st State
			if json.Unmarshal([]byte(strings.TrimSpace(raw)), &st) != nil {
				continue
			}
			select {
			case out <- st:
			default:
			}
		}
	}()
	return out, cancel
}

func awaitPhase(t *testing.T, states <-chan State, want client.Phase, within time.Duration) {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case st, ok := <-states:
			if !ok {
				t.Fatal("the stream ended")
			}
			if st.Session.Phase == want {
				return
			}
		case <-deadline:
			t.Fatalf("the page was never told the session was %q", want)
		}
	}
}

// The page is not the only thing that can act. A tray menu connects and
// disconnects, and a page that was only ever told about challenges went on
// showing what was true when somebody last clicked something -- which is how
// the menu bar and the window came to disagree about whether the client was
// even connected.
func TestConnectingElsewhereReachesThePage(t *testing.T) {
	_, ctl, _, srv := testServer(t)

	states, cancel := openStream(t, srv.URL)
	defer cancel()

	// The opening state, before anything happens.
	select {
	case st := <-states:
		if st.Session.Phase != client.PhaseIdle {
			t.Fatalf("the stream opened on %q, want idle", st.Session.Phase)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the stream sent nothing when it opened")
	}

	// Somebody connects from the tray, not from this page.
	if err := ctl.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitPhase(t, states, client.PhaseConnected, 5*time.Second)

	// And disconnects again, also not from this page.
	if err := ctl.Disconnect(); err != nil {
		t.Fatal(err)
	}
	awaitPhase(t, states, client.PhaseIdle, 5*time.Second)
}

// Settings changed in another window have to arrive too.
func TestSettingsChangedElsewhereReachThePage(t *testing.T) {
	_, ctl, _, srv := testServer(t)

	states, cancel := openStream(t, srv.URL)
	defer cancel()
	<-states // the opening state

	next := *ctl.Settings()
	next.AutoDomains = !next.AutoDomains
	if err := ctl.Apply(context.Background(), &next); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case st, ok := <-states:
			if !ok {
				t.Fatal("the stream ended")
			}
			if st.Client.AutoDomains == next.AutoDomains {
				return
			}
		case <-deadline:
			t.Fatal("a settings change made elsewhere never reached the page")
		}
	}
}

// A stream that has nothing to say says nothing: the page is not asked to
// re-render once a second for no reason.
func TestAStreamWithNothingToSayIsQuiet(t *testing.T) {
	_, _, _, srv := testServer(t)

	states, cancel := openStream(t, srv.URL)
	defer cancel()
	<-states // the opening state

	select {
	case st, ok := <-states:
		if ok {
			t.Fatalf("the stream sent an update with nothing changed: %+v", st.Session)
		}
	case <-time.After(4 * time.Second):
	}
}
