//go:build desktop

package main

import "fmt"

// The tray carries its own strings: it is drawn before the interface loads
// and has to be readable in the menu bar on its own.
var trayStrings = map[string]map[string]string{
	"zh": {
		"title":       "vpn-gateway",
		"description": "多 VPN 分流网关",

		"open":       "打开控制台",
		"connect":    "连接",
		"disconnect": "断开",
		"quit":       "退出",

		"status.setup":       "尚未配置",
		"status.idle":        "未连接（%d 条隧道）",
		"status.connecting":  "连接中…",
		"status.failed":      "连接失败",
		"status.up":          "%d/%d 条隧道在线",
		"status.unreachable": "后台服务没有响应",

		"tunnel.up":   "在线",
		"tunnel.down": "离线",

		"tip.setup":       "vpn-gateway — 打开窗口完成配置",
		"tip.idle":        "vpn-gateway — 未连接",
		"tip.connecting":  "vpn-gateway — 连接中",
		"tip.failed":      "vpn-gateway — 连接失败",
		"tip.ok":          "vpn-gateway — %d/%d 条隧道在线",
		"tip.unreachable": "vpn-gateway — 后台服务在运行，但界面连不上",
	},
	"en": {
		"title":       "vpn-gateway",
		"description": "Several VPNs at once, split by rule",

		"open":       "Open console",
		"connect":    "Connect",
		"disconnect": "Disconnect",
		"quit":       "Quit",

		"status.setup":       "Not set up yet",
		"status.idle":        "Not connected (%d tunnels)",
		"status.connecting":  "Connecting…",
		"status.failed":      "Could not connect",
		"status.up":          "%d/%d tunnels up",
		"status.unreachable": "The service is not answering",

		"tunnel.up":   "up",
		"tunnel.down": "down",

		"tip.setup":       "vpn-gateway — open the window to set it up",
		"tip.idle":        "vpn-gateway — not connected",
		"tip.connecting":  "vpn-gateway — connecting",
		"tip.failed":      "vpn-gateway — could not connect",
		"tip.ok":          "vpn-gateway — %d/%d tunnels up",
		"tip.unreachable": "vpn-gateway — the background service is running but its interface cannot be reached",
	},
}

// translator returns a lookup for one language, falling back to English for
// anything that language is missing.
//
// A missing string comes back as its own key rather than as nothing. A blank
// menu entry looks like a bug in the application; a visible key says which
// string is absent.
func translator(lang string) func(string, ...any) string {
	table, ok := trayStrings[lang]
	if !ok {
		table = trayStrings["en"]
	}
	return func(key string, args ...any) string {
		s, ok := table[key]
		if !ok {
			s, ok = trayStrings["en"][key]
		}
		if !ok {
			return key
		}
		if len(args) == 0 {
			return s
		}
		return fmt.Sprintf(s, args...)
	}
}
