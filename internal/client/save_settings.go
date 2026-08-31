package client

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// settingsKeys are the fields the interface owns. Anything else in the file
// is left exactly as written, comments included.
var settingsKeys = []string{
	"bundle", "tun", "proxy", "dns", "auth", "on_failure",
	"auto_routes", "auto_domains", "rules", "disabled_auto_rules", "ui", "log_level",
}

// SaveSettings writes a configuration back, replacing only the keys the
// interface manages and leaving the rest of the document untouched.
//
// Re-encoding the whole struct would throw away every comment someone wrote,
// and a configuration file whose comments vanish the first time it is touched
// through the interface is one nobody will annotate again.
func SaveSettings(path string, cfg *Config) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read the configuration: %w", err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse the configuration: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return fmt.Errorf("%s is not a YAML document", path)
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("%s does not contain a mapping at the top level", path)
	}

	// Render the whole configuration once, then graft across only the keys
	// the interface owns.
	var whole yaml.Node
	if err := whole.Encode(cfg); err != nil {
		return fmt.Errorf("encode the configuration: %w", err)
	}
	fresh := map[string]*yaml.Node{}
	for i := 0; i+1 < len(whole.Content); i += 2 {
		fresh[whole.Content[i].Value] = whole.Content[i+1]
	}

	for _, key := range settingsKeys {
		value, ok := fresh[key]
		if !ok {
			continue
		}
		replaced := false
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == key {
				// The key node stays, and with it any comment above it.
				root.Content[i+1] = value
				replaced = true
				break
			}
		}
		if !replaced {
			root.Content = append(root.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
		}
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("render the configuration: %w", err)
	}
	return writeAtomically(path, out)
}

// writeInitialConfig creates a configuration file for a session that had
// none, with a header explaining where it came from.
func writeInitialConfig(path string, cfg *Config) error {
	body, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode the configuration: %w", err)
	}
	header := "# Written by the vpn-gateway application.\n" +
		"# Editing this by hand is fine; the interface preserves comments.\n\n"
	return writeAtomically(path, append([]byte(header), body...))
}
