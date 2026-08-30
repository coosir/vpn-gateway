//go:build desktop

package main

import "fmt"

// The tray carries its own strings: it starts before the interface loads and
// has to be readable in the menu bar on its own.
var strings_ = map[string]map[string]string{
	"zh": {
		"title":        "vpn-gateway",
		"description":  "多 VPN 分流网关",
		"fail.title":   "无法连接到 vpn-gateway 客户端",
		"open":         "打开控制台",
		"quit":         "退出",
		"status.up":    "%d/%d 条隧道在线",
		"status.none":  "没有隧道",
		"status.gone":  "客户端未运行",
		"tunnels":      "隧道",
		"tunnel.up":    "在线",
		"tunnel.down":  "离线",
		"auth.waiting": "需要验证码",
		"tip.ok":       "vpn-gateway — %d/%d 条隧道在线",
		"tip.gone":     "vpn-gateway — 客户端未运行",
	},
	"en": {
		"title":        "vpn-gateway",
		"description":  "多 VPN 分流网关",
		"fail.title":   "无法连接到 vpn-gateway 客户端",
		"open":         "Open console",
		"quit":         "Quit",
		"status.up":    "%d/%d tunnels up",
		"status.none":  "No tunnels",
		"status.gone":  "Client not running",
		"tunnels":      "Tunnels",
		"tunnel.up":    "up",
		"tunnel.down":  "down",
		"auth.waiting": "waiting for a code",
		"tip.ok":       "vpn-gateway — %d/%d tunnels up",
		"tip.gone":     "vpn-gateway — client not running",
	},
}

// translator returns a lookup for one language, falling back to English for
// anything the language is missing.
func translator(lang string) func(string, ...any) string {
	table, ok := strings_[lang]
	if !ok {
		table = strings_["en"]
	}
	return func(key string, args ...any) string {
		s, ok := table[key]
		if !ok {
			s = strings_["en"][key]
		}
		if len(args) == 0 {
			return s
		}
		return fmt.Sprintf(s, args...)
	}
}
