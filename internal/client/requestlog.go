package client

import (
	"regexp"
	"strings"
	"sync"
	"time"

	boxlog "github.com/sagernet/sing-box/log"
)

const requestLogLimit = 500

var requestIDPattern = regexp.MustCompile(`\[(\d+) [^]]+\]`)
var ansiColorPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// RequestEntry describes a connection's routing decision, not its contents.
type RequestEntry struct {
	Time        time.Time `json:"time"`
	Destination string    `json:"destination"`
	Domain      string    `json:"domain,omitempty"`
	Network     string    `json:"network"`
	Inbound     string    `json:"inbound"`
	Process     string    `json:"process,omitempty"`
	Rule        string    `json:"rule"`
	Outbound    string    `json:"outbound"`
	Status      string    `json:"status"`
	requestID   string
}

// RequestLog receives sing-box's connection-scoped platform messages. It is
// disabled by default and keeps only the most recent requests in memory.
type RequestLog struct {
	mu      sync.Mutex
	enabled bool
	entries []*RequestEntry
	byID    map[string]*RequestEntry
}

func NewRequestLog(enabled bool) *RequestLog {
	return &RequestLog{enabled: enabled, byID: make(map[string]*RequestEntry)}
}

func (l *RequestLog) Enable(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.enabled == enabled {
		return
	}
	l.enabled = enabled
	l.clear()
}

func (l *RequestLog) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clear()
}

func (l *RequestLog) clear() {
	l.entries = nil
	l.byID = make(map[string]*RequestEntry)
}

func (l *RequestLog) Snapshot() []RequestEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]RequestEntry, len(l.entries))
	for i, entry := range l.entries {
		out[len(l.entries)-1-i] = *entry
	}
	return out
}

func (l *RequestLog) WriteMessage(level boxlog.Level, message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.enabled {
		return
	}
	message = ansiColorPattern.ReplaceAllString(message, "")
	idMatch := requestIDPattern.FindStringSubmatch(message)
	if len(idMatch) < 2 {
		return
	}
	id := idMatch[1]
	// Each inbound connection starts one row. The correlation ID also follows
	// process discovery and rule matching, including DNS and rejected traffic.
	if at := strings.Index(message, "inbound connection to "); at >= 0 || strings.Contains(message, "inbound packet connection to ") {
		network := "TCP"
		if at < 0 {
			at = strings.Index(message, "inbound packet connection to ")
			network = "UDP"
			at += len("inbound packet connection to ")
		} else {
			at += len("inbound connection to ")
		}
		dest := strings.TrimSpace(message[at:])
		if dest == "" {
			return
		}
		inbound := ""
		if start := strings.Index(message, "inbound/"); start >= 0 {
			if end := strings.Index(message[start:], ":"); end >= 0 {
				inbound = message[start : start+end]
			}
		}
		entry := &RequestEntry{Time: time.Now(), Destination: dest, Network: network, Inbound: inbound, Rule: "final", Status: "routed", requestID: id}
		l.entries = append(l.entries, entry)
		l.byID[id] = entry
		if len(l.entries) > requestLogLimit {
			oldest := l.entries[0]
			l.entries = l.entries[1:]
			if l.byID[oldest.requestID] == oldest {
				delete(l.byID, oldest.requestID)
			}
		}
		return
	}
	entry := l.byID[id]
	if entry == nil {
		return
	}
	if at := strings.Index(message, "found process path: "); at >= 0 {
		entry.Process = strings.SplitN(strings.TrimSpace(message[at+len("found process path: "):]), ",", 2)[0]
	}
	if at := strings.Index(message, "sniffed protocol: "); at >= 0 || strings.Contains(message, "sniffed packet protocol: ") {
		if domain := strings.Index(message, ", domain: "); domain >= 0 {
			entry.Domain = strings.SplitN(strings.TrimSpace(message[domain+len(", domain: "):]), ",", 2)[0]
		}
	}
	if at := strings.Index(message, "match["); at >= 0 && strings.Contains(message, "router: ") {
		decision := strings.TrimSpace(message[at:])
		if strings.Contains(decision, " => route(") || strings.HasSuffix(decision, " => reject") || strings.Contains(decision, " => reject(") || strings.HasSuffix(decision, " => hijack-dns") {
			entry.Rule = strings.SplitN(decision, " => ", 2)[0]
			if action := strings.SplitN(decision, " => ", 2); len(action) == 2 {
				if strings.HasPrefix(action[1], "route(") {
					entry.Outbound = strings.SplitN(strings.TrimPrefix(action[1], "route("), ",", 2)[0]
					entry.Outbound = strings.TrimSuffix(entry.Outbound, ")")
				} else if action[1] == "hijack-dns" {
					entry.Outbound = "dns"
				} else {
					entry.Outbound, entry.Status = "block", "blocked"
				}
			}
		}
	}
	if strings.Contains(message, "outbound/") && (strings.Contains(message, "outbound connection to ") || strings.Contains(message, "outbound packet connection to ")) {
		at := strings.Index(message, "outbound/")
		if end := strings.Index(message[at:], ":"); end >= 0 {
			tag := message[at : at+end]
			actual := strings.TrimPrefix(tag, "outbound/")
			if start := strings.Index(tag, "["); start >= 0 && strings.HasSuffix(tag, "]") {
				actual = tag[start+1 : len(tag)-1]
			}
			if entry.Outbound != "" && entry.Outbound != actual {
				entry.Outbound += " → " + actual
			} else {
				entry.Outbound = actual
			}
		}
	}
	if level <= boxlog.LevelError && (strings.Contains(message, "router: ") || strings.Contains(message, "connection: ")) {
		entry.Status = "failed"
	}
}
