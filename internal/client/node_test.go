package client

import (
	"encoding/base64"
	"testing"
)

func TestParseTrojanURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		check   func(*testing.T, *CustomNode)
	}{
		{
			name: "standard url with fragment and query",
			url:  "trojan://mypassword@example.com:443?sni=sni.example.com&allowInsecure=1#HongKong-01",
			check: func(t *testing.T, n *CustomNode) {
				if n.Password != "mypassword" {
					t.Errorf("Password = %q, want mypassword", n.Password)
				}
				if n.Server != "example.com" || n.Port != 443 {
					t.Errorf("Server:Port = %s:%d, want example.com:443", n.Server, n.Port)
				}
				if n.SNI != "sni.example.com" {
					t.Errorf("SNI = %q, want sni.example.com", n.SNI)
				}
				if !n.AllowInsecure {
					t.Errorf("AllowInsecure = %v, want true", n.AllowInsecure)
				}
				if n.Name != "HongKong-01" {
					t.Errorf("Name = %q, want HongKong-01", n.Name)
				}
			},
		},
		{
			name: "url without port defaults to 443",
			url:  "trojan://secret@us.node.com#US+Node",
			check: func(t *testing.T, n *CustomNode) {
				if n.Port != 443 {
					t.Errorf("Port = %d, want 443", n.Port)
				}
				if n.SNI != "us.node.com" {
					t.Errorf("SNI = %s, want us.node.com", n.SNI)
				}
				if n.Name != "US Node" {
					t.Errorf("Name = %s, want 'US Node'", n.Name)
				}
			},
		},
		{
			name:    "invalid scheme",
			url:     "ss://password@example.com:443",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := ParseTrojanURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseTrojanURL() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && tt.check != nil {
				tt.check(t, node)
			}
		})
	}
}

func TestParseSubscription(t *testing.T) {
	t.Run("plain text list", func(t *testing.T) {
		content := `
# some comment
trojan://pass1@hk.node.com:443#HK
trojan://pass2@us.node.com:8443#US
`
		nodes, err := ParseSubscription([]byte(content))
		if err != nil {
			t.Fatalf("ParseSubscription() error = %v", err)
		}
		if len(nodes) != 2 {
			t.Fatalf("got %d nodes, want 2", len(nodes))
		}
		if nodes[0].Name != "HK" || nodes[1].Name != "US" {
			t.Errorf("unexpected nodes: %+v", nodes)
		}
	})

	t.Run("base64 encoded list", func(t *testing.T) {
		raw := "trojan://pass1@hk.node.com:443#HK\ntrojan://pass2@us.node.com:8443#US\n"
		encoded := base64.StdEncoding.EncodeToString([]byte(raw))
		nodes, err := ParseSubscription([]byte(encoded))
		if err != nil {
			t.Fatalf("ParseSubscription() error = %v", err)
		}
		if len(nodes) != 2 {
			t.Fatalf("got %d nodes, want 2", len(nodes))
		}
	})

	t.Run("clash yaml", func(t *testing.T) {
		clash := `
proxies:
  - name: "HK-Clash"
    type: trojan
    server: "hk.clash.com"
    port: 443
    password: "secretpassword"
    sni: "sni.clash.com"
    skip-cert-verify: true
`
		nodes, err := ParseSubscription([]byte(clash))
		if err != nil {
			t.Fatalf("ParseSubscription() error = %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("got %d nodes, want 1", len(nodes))
		}
		if nodes[0].Name != "HK-Clash" || nodes[0].Server != "hk.clash.com" || !nodes[0].AllowInsecure {
			t.Errorf("unexpected node: %+v", nodes[0])
		}
	})
}
