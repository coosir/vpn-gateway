package client

import (
	"fmt"
	"strings"
	"testing"
	"time"

	boxlog "github.com/sagernet/sing-box/log"
)

func TestRequestLogTracksRoutingAndRespectsSwitch(t *testing.T) {
	l := NewRequestLog(false)
	inbound := "INFO[0001] [\x1b[38;5;226m42\x1b[0m 0ms] inbound/tun[tun-in]: inbound connection to example.com:443"
	l.WriteMessage(boxlog.LevelInfo, inbound)
	if len(l.Snapshot()) != 0 {
		t.Fatal("recorded while disabled")
	}
	l.Enable(true)
	l.WriteMessage(boxlog.LevelInfo, inbound)
	l.WriteMessage(boxlog.LevelInfo, "INFO[0001] [42 1ms] router: found process path: C:\\Browser\\browser.exe")
	l.WriteMessage(boxlog.LevelDebug, "DEBUG[0001] [42 2ms] router: match[3] domain_suffix=example.com => route(proxy)")
	l.WriteMessage(boxlog.LevelDebug, "DEBUG[0001] [42 2ms] router: sniffed protocol: tls, domain: example.com")
	l.WriteMessage(boxlog.LevelInfo, "INFO[0001] [42 3ms] outbound/shadowsocks[node-1]: outbound connection to example.com:443")
	entry := l.Snapshot()[0]
	if entry.Destination != "example.com:443" || entry.Network != "TCP" || entry.Inbound != "inbound/tun[tun-in]" ||
		!strings.Contains(entry.Rule, "domain_suffix=example.com") || entry.Outbound != "proxy → node-1" || entry.Process == "" || entry.Domain != "example.com" {
		t.Fatalf("wrong request entry: %+v", entry)
	}
	l.Clear()
	if len(l.Snapshot()) != 0 {
		t.Fatal("clear kept entries")
	}
	l.WriteMessage(boxlog.LevelInfo, inbound)
	l.Enable(false)
	if len(l.Snapshot()) != 0 {
		t.Fatal("disable kept entries")
	}
}

func TestRequestLogCapturesLiveRoutingDecision(t *testing.T) {
	cfg := baseConfig()
	cfg.RequestLog = true
	cfg.AutoRoutes = false
	cfg.AutoDomains = false
	cfg.Rules = []Rule{{DomainSuffix: []string{"office.example.com"}, Tunnel: "office"}}
	stack := startFullStack(t, cfg, "office")
	if got, err := stack.get("a.office.example.com"); err != nil || got != "office" {
		t.Fatalf("request: %q, %v", got, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, entry := range stack.client.Requests().Snapshot() {
			if !strings.Contains(entry.Destination, "a.office.example.com") {
				continue
			}
			if !strings.Contains(entry.Rule, "office.example.com") || !strings.Contains(entry.Outbound, "route-office") {
				t.Fatalf("wrong live routing decision: %+v", entry)
			}
			stack.client.Requests().Enable(false)
			if len(stack.client.Requests().Snapshot()) != 0 {
				t.Fatal("disable left live requests in memory")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("live request was not recorded")
}

func TestRequestLogBoundsEntriesAndRecordsReject(t *testing.T) {
	l := NewRequestLog(true)
	for i := 0; i <= requestLogLimit; i++ {
		l.WriteMessage(boxlog.LevelInfo, fmt.Sprintf("INFO[0001] [%d 0ms] inbound/tun[tun-in]: inbound packet connection to host-%d:53", i, i))
	}
	entries := l.Snapshot()
	if len(entries) != requestLogLimit || entries[0].Destination != "host-500:53" || entries[len(entries)-1].Destination != "host-1:53" {
		t.Fatalf("wrong bounded log: first=%+v count=%d", entries[0], len(entries))
	}
	l.WriteMessage(boxlog.LevelDebug, "DEBUG[0001] [500 1ms] router: match[4] domain_suffix=blocked.test => reject")
	if entries = l.Snapshot(); entries[0].Status != "blocked" || entries[0].Outbound != "block" {
		t.Fatalf("rejected request: %+v", entries[0])
	}
	l.WriteMessage(boxlog.LevelInfo, "INFO[0001] [499 2ms] outbound/direct[direct]: outbound packet connection to host-499:53")
	if entries = l.Snapshot(); entries[1].Outbound != "direct" {
		t.Fatalf("UDP outbound: %+v", entries[1])
	}
}

func TestRequestLogSwitchFailsClosedWhenConfigCannotBeSaved(t *testing.T) {
	cfg := baseConfig()
	cfg.RequestLog = true
	log := NewRequestLog(true)
	s := &Session{configPath: t.TempDir(), cfg: cfg, client: &Client{requests: log}}
	if err := s.SetRequestLogging(false); err == nil {
		t.Fatal("expected save failure")
	}
	log.WriteMessage(boxlog.LevelInfo, "INFO[0001] [1 0ms] inbound/tun[tun-in]: inbound connection to example.com:443")
	if len(log.Snapshot()) != 0 || s.Settings().RequestLog {
		t.Fatal("failed disable left request logging on")
	}
	if err := s.SetRequestLogging(true); err == nil {
		t.Fatal("expected save failure")
	}
	if s.Settings().RequestLog {
		t.Fatal("failed enable changed displayed setting")
	}
}

func TestRequestLogSwitchUpdatesEngineConfigForLaterReload(t *testing.T) {
	c := &Client{cfg: &Config{}, requests: NewRequestLog(false)}
	c.SetRequestLogging(true)
	if !c.Settings().RequestLog {
		t.Fatal("running config still has old request log setting")
	}
	c.SetRequestLogging(false)
	if c.Settings().RequestLog {
		t.Fatal("running config still enables request log")
	}
}
