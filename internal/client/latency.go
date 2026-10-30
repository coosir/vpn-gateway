package client

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"
)

// latencyURL is what a latency test fetches through a node. It answers with
// an empty 204 from close to everywhere, so what is measured is the node.
const latencyURL = "https://www.gstatic.com/generate_204"

const (
	latencyTimeout     = 6 * time.Second
	latencyConcurrency = 16
)

// Latency results are milliseconds; LatencyFailed marks a node that did not
// answer at all.
const LatencyFailed = -1

// TestLatency measures a real HTTP round trip through each node, keyed by
// node ID.
//
// A TCP or TLS handshake with the server says little about a node: it is the
// same for a node that works and one whose credentials are wrong, and means
// nothing at all for one that runs over QUIC. Going through the node is the
// only measurement that says whether it carries traffic. When an engine is
// running its outbounds are used; otherwise a short-lived engine holding only
// the nodes is built for the purpose.
func TestLatency(ctx context.Context, running *Client, nodes []CustomNode) (map[string]int, error) {
	if running != nil {
		running.instanceMu.Lock()
		instance := running.instance
		running.instanceMu.Unlock()
		if instance != nil {
			return measure(ctx, nodes, func(tag string) (N.Dialer, bool) {
				ob, ok := instance.Outbound().Outbound(tag)
				return ob, ok
			}), nil
		}
	}

	var outbounds []map[string]any
	var usable []CustomNode
	results := map[string]int{}
	for _, n := range nodes {
		ob, err := n.Outbound()
		if err != nil {
			results[n.ID] = LatencyFailed
			continue
		}
		outbounds = append(outbounds, ob)
		usable = append(usable, n)
	}
	if len(usable) == 0 {
		return results, nil
	}
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": tagDirect})
	raw, err := json.Marshal(map[string]any{
		"log":       map[string]any{"disabled": true},
		"dns":       map[string]any{"servers": []map[string]any{{"type": "local", "tag": "local"}}},
		"outbounds": outbounds,
		"route": map[string]any{
			"default_domain_resolver": map[string]any{"server": "local"},
			"final":                   tagDirect,
		},
	})
	if err != nil {
		return nil, err
	}
	boxCtx := registryContext(ctx)
	var opts option.Options
	if err := singjson.UnmarshalContext(boxCtx, raw, &opts); err != nil {
		return nil, fmt.Errorf("prepare the latency test: %w", err)
	}
	instance, err := box.New(box.Options{Context: boxCtx, Options: opts})
	if err != nil {
		return nil, fmt.Errorf("prepare the latency test: %w", err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		return nil, fmt.Errorf("start the latency test: %w", err)
	}
	defer instance.Close()

	for id, ms := range measure(ctx, usable, func(tag string) (N.Dialer, bool) {
		ob, ok := instance.Outbound().Outbound(tag)
		return ob, ok
	}) {
		results[id] = ms
	}
	return results, nil
}

func measure(ctx context.Context, nodes []CustomNode, outbound func(tag string) (N.Dialer, bool)) map[string]int {
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results = make(map[string]int, len(nodes))
		slots   = make(chan struct{}, latencyConcurrency)
	)
	for _, n := range nodes {
		dialer, ok := outbound(n.OutboundTag())
		if !ok {
			results[n.ID] = LatencyFailed
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			testCtx, cancel := context.WithTimeout(ctx, latencyTimeout)
			defer cancel()
			ms := LatencyFailed
			if delay, err := urltest.URLTest(testCtx, latencyURL, dialer); err == nil {
				ms = int(delay)
			}
			mu.Lock()
			results[n.ID] = ms
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}
