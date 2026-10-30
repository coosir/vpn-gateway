package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Geosite and geoip rules are SagerNet's compiled rule sets, fetched through
// jsDelivr: GitHub's own raw host is unreachable from some of the places this
// client is most needed, and jsDelivr usually is not.
const (
	geositeURL = "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-%s.srs"
	geoipURL   = "https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-%s.srs"

	// ruleSetMaxAge is how old a downloaded rule set may get before it is
	// fetched again. A stale one is still used when fetching fails.
	ruleSetMaxAge = 7 * 24 * time.Hour
)

// The rule sets are local files rather than sing-box's own remote rule sets.
// sing-box will not start until every remote set has been downloaded at
// least once, so one rule naming a set the network cannot reach would keep
// the whole client -- gateway included -- from connecting. Fetched here, a
// set that cannot be had only means the rules using it are left out.

func geositeTag(name string) string { return "geosite-" + name }
func geoipTag(name string) string   { return "geoip-" + name }

func ruleSetURL(tag string) string {
	if name, ok := strings.CutPrefix(tag, "geosite-"); ok {
		return fmt.Sprintf(geositeURL, name)
	}
	name, _ := strings.CutPrefix(tag, "geoip-")
	return fmt.Sprintf(geoipURL, name)
}

// ruleSetDir is where rule sets are kept for this configuration.
func (c *Config) ruleSetDir() string {
	if c.RuleSetDir != "" {
		return c.RuleSetDir
	}
	return filepath.Join(DefaultStateDir(), "rule-sets")
}

func (c *Config) ruleSetPath(tag string) string {
	return filepath.Join(c.ruleSetDir(), tag+".srs")
}

// ruleSetReady reports whether a rule set has been downloaded.
func (c *Config) ruleSetReady(tag string) bool {
	info, err := os.Stat(c.ruleSetPath(tag))
	return err == nil && info.Size() > 0
}

// ruleTags lists the rule sets one rule refers to.
func (r Rule) ruleTags() []string {
	var tags []string
	for _, name := range r.GeoSite {
		tags = append(tags, geositeTag(name))
	}
	for _, name := range r.GeoIP {
		tags = append(tags, geoipTag(name))
	}
	return tags
}

// neededRuleSets lists every rule set the engine would use, given whether the
// gateway is part of it.
func neededRuleSets(cfg *Config, gateway bool) []string {
	seen := map[string]bool{}
	add := func(rules []Rule) {
		for _, r := range rules {
			if r.Disabled {
				continue
			}
			for _, tag := range r.ruleTags() {
				seen[tag] = true
			}
		}
	}
	if gateway {
		add(cfg.Rules)
	}
	if cfg.EffectiveMode() == ModeRule {
		add(cfg.ProxyRules)
	}
	tags := make([]string, 0, len(seen))
	for tag := range seen {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

// dialFunc opens a connection for a download: directly, or through a running
// engine's proxy group.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// fetchRuleSets downloads the rule sets that are missing or stale, in
// parallel, and returns what went wrong with each one that could not be had.
// A stale set that fails to refresh is not an error: it is still there.
func fetchRuleSets(ctx context.Context, cfg *Config, tags []string, dial dialFunc) map[string]error {
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		errs = map[string]error{}
	)
	for _, tag := range tags {
		path := cfg.ruleSetPath(tag)
		info, err := os.Stat(path)
		if err == nil && info.Size() > 0 && time.Since(info.ModTime()) < ruleSetMaxAge {
			continue
		}
		have := err == nil && info.Size() > 0
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := downloadRuleSet(ctx, ruleSetURL(tag), path, dial); err != nil && !have {
				mu.Lock()
				errs[tag] = err
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return errs
}

func downloadRuleSet(ctx context.Context, link, path string, dial dialFunc) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	transport := &http.Transport{Proxy: nil}
	if dial != nil {
		transport.DialContext = dial
	}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", link, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return fmt.Errorf("%s is empty", link)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// Written beside the target and renamed into place, so an engine reading
	// the old file never sees half of the new one.
	tmp := path + ".part"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
