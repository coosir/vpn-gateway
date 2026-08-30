package client

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// SaveRules writes rules back into the configuration file, replacing the
// rules section and leaving everything else exactly as it was.
//
// The file is edited as a YAML document tree rather than re-encoded from the
// Config struct. Re-encoding would throw away every comment the person wrote,
// and a configuration file whose comments vanish the first time someone
// touches the interface is a file nobody will annotate again.
func SaveRules(path string, rules []Rule) error {
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

	// Encode the new rules on their own, then graft the resulting sequence in.
	var encoded yaml.Node
	if err := encoded.Encode(rules); err != nil {
		return fmt.Errorf("encode the rules: %w", err)
	}
	if len(rules) == 0 {
		// An empty sequence, so the key stays present and obvious rather than
		// disappearing and looking like it was never there.
		encoded = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
	}

	replaced := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "rules" {
			// Keep the key node, and with it any comment written above it.
			root.Content[i+1] = &encoded
			replaced = true
			break
		}
	}
	if !replaced {
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "rules"},
			&encoded)
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("render the configuration: %w", err)
	}
	return writeAtomically(path, out)
}

// writeAtomically replaces path in one step, so an interrupted write cannot
// leave a client with a half-written configuration and no way to start.
func writeAtomically(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("prepare %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".vpn-gateway-*.yaml")
	if err != nil {
		return fmt.Errorf("create a temporary file next to the configuration: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	// Match the mode of the file being replaced; the configuration names a
	// bundle full of tunnel passwords.
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return fmt.Errorf("write the configuration: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
