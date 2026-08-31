package client

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// SaveRules writes rules back into the configuration file, replacing the
// rules section and leaving everything else exactly as it was.
func SaveRules(path string, rules []Rule) error {
	return SaveRulesAndDisabledAuto(path, rules, nil)
}

// SaveRulesAndDisabledAuto writes rules and disabled auto-rule keys back into the configuration file.
func SaveRulesAndDisabledAuto(path string, rules []Rule, disabledAuto []string) error {
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

	// 1. Rules
	var encodedRules yaml.Node
	if err := encodedRules.Encode(rules); err != nil {
		return fmt.Errorf("encode the rules: %w", err)
	}
	if len(rules) == 0 {
		encodedRules = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
	}
	replaceOrAppendNode(root, "rules", &encodedRules)

	// 2. DisabledAutoRules
	if disabledAuto != nil {
		var encodedDisabled yaml.Node
		if err := encodedDisabled.Encode(disabledAuto); err != nil {
			return fmt.Errorf("encode disabled auto rules: %w", err)
		}
		if len(disabledAuto) == 0 {
			encodedDisabled = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
		}
		replaceOrAppendNode(root, "disabled_auto_rules", &encodedDisabled)
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("render the configuration: %w", err)
	}
	return writeAtomically(path, out)
}

func replaceOrAppendNode(root *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			root.Content[i+1] = val
			return
		}
	}
	root.Content = append(root.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		val)
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
	if err := preserveOwner(tmp, path); err != nil {
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
