package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeClientConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestRuleJSONAndYAMLNamesAgree guards a mismatch that silently emptied a
// person's rules: the interface reads and writes them over JSON and saves
// them back to the YAML file, so the two encodings have to name the same
// fields.
func TestRuleJSONAndYAMLNamesAgree(t *testing.T) {
	rt := reflect.TypeOf(Rule{})
	for i := range rt.NumField() {
		f := rt.Field(i)
		yamlName := strings.Split(f.Tag.Get("yaml"), ",")[0]
		jsonName := strings.Split(f.Tag.Get("json"), ",")[0]
		if yamlName == "" || jsonName == "" {
			t.Errorf("%s: yaml=%q json=%q, both are required", f.Name, yamlName, jsonName)
			continue
		}
		if yamlName != jsonName {
			t.Errorf("%s: yaml calls it %q and json calls it %q", f.Name, yamlName, jsonName)
		}
	}
}

// TestRuleRoundTripsThroughJSONAndYAML exercises the whole path the interface
// takes: read as JSON, write back as YAML, load again.
func TestRuleRoundTripsThroughJSONAndYAML(t *testing.T) {
	original := []Rule{
		{DomainSuffix: []string{"corp.example.com"}, IPCIDR: []string{"10.20.0.0/16"}, Tunnel: "office"},
		{DomainKeyword: []string{"gitlab"}, Port: []int{443}, Tunnel: "lab"},
		{Domain: []string{"ads.example.com"}, Tunnel: TargetBlock},
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []Rule
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}

	path := writeClientConfig(t, "bundle: /dev/null\nproxy: {enabled: true}\n")
	if err := SaveRules(path, decoded); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.Rules, original) {
		t.Errorf("rules changed on the way through:\n got %+v\nwant %+v", cfg.Rules, original)
	}
}

func TestClientConfigDefaults(t *testing.T) {
	path := writeClientConfig(t, "bundle: /etc/vpn-gateway/client.json\nproxy: {enabled: true}\n")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.OnFailure != TargetDirect {
		t.Errorf("on_failure = %q, want direct", cfg.OnFailure)
	}
	if cfg.Proxy.Listen != "127.0.0.1:1080" {
		t.Errorf("proxy.listen = %q", cfg.Proxy.Listen)
	}
	if cfg.UI.Listen == "" {
		t.Error("ui.listen has no default")
	}
}

func TestClientConfigRequiresAWayIn(t *testing.T) {
	// With neither a TUN interface nor a proxy port there is nothing for
	// traffic to enter through, and the client would run doing nothing.
	path := writeClientConfig(t, "bundle: /etc/vpn-gateway/client.json\n")
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("a configuration with no ingress was accepted")
	}
}

func TestUIMustBeOnLoopback(t *testing.T) {
	// The interface can reroute this machine's traffic; reachable from the
	// network it would let a stranger do it.
	path := writeClientConfig(t, `
bundle: /etc/vpn-gateway/client.json
proxy: {enabled: true}
ui: {enabled: true, listen: "0.0.0.0:8645"}
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("a non-loopback interface address was accepted")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("the error does not explain why: %v", err)
	}
}

func TestRuleWithNoMatcherIsRejected(t *testing.T) {
	path := writeClientConfig(t, `
bundle: /etc/vpn-gateway/client.json
proxy: {enabled: true}
rules:
  - tunnel: office
`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("a rule matching nothing was accepted")
	}
}

func TestDefaultResolverIsReachableEverywhere(t *testing.T) {
	// The default has to work on any network. A public resolver over HTTPS is
	// more private, but several are blocked in some countries, and one that
	// times out looks like the whole client is broken rather than like a DNS
	// problem.
	path := writeClientConfig(t, "bundle: /dev/null\nproxy: {enabled: true}\n")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.Default != "local" {
		t.Errorf("dns.default = %q, want local", cfg.DNS.Default)
	}
}

func TestExplicitResolverIsKept(t *testing.T) {
	path := writeClientConfig(t, `
bundle: /dev/null
proxy: {enabled: true}
dns: {default: "https://1.1.1.1/dns-query"}
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.Default != "https://1.1.1.1/dns-query" {
		t.Errorf("dns.default = %q", cfg.DNS.Default)
	}
}
