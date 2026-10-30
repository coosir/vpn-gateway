package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Node protocols. The names are sing-box's own outbound types, so a node's
// type is what its outbound is called.
const (
	NodeTrojan      = "trojan"
	NodeVMess       = "vmess"
	NodeVLESS       = "vless"
	NodeShadowsocks = "shadowsocks"
	NodeHysteria2   = "hysteria2"
	NodeTUIC        = "tuic"
	NodeAnyTLS      = "anytls"
	NodeSOCKS       = "socks"
	NodeHTTP        = "http"
)

// nodePrefix tags every node's outbound.
const nodePrefix = "node-"

// CustomNode is one proxy server, added by hand or delivered by a
// subscription.
//
// It is one flat struct for every protocol rather than one per protocol: a
// node arrives as a link or a Clash entry, is edited in one form and stored
// in one list, and each protocol reads only the fields it has.
type CustomNode struct {
	ID     string `yaml:"id" json:"id"`
	Name   string `yaml:"name" json:"name"`
	Type   string `yaml:"type" json:"type"`
	Server string `yaml:"server" json:"server"`
	Port   int    `yaml:"port" json:"port"`

	// Password is trojan's, shadowsocks', hysteria2's, tuic's, anytls's, and
	// the optional one of socks and http.
	Password string `yaml:"password,omitempty" json:"password,omitempty"`
	// Username belongs to socks and http.
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	// UUID identifies the user to vmess, vless and tuic.
	UUID string `yaml:"uuid,omitempty" json:"uuid,omitempty"`
	// Method is shadowsocks' cipher, or vmess's security ("auto" if empty).
	Method  string `yaml:"method,omitempty" json:"method,omitempty"`
	AlterID int    `yaml:"alter_id,omitempty" json:"alter_id,omitempty"`
	// Flow is vless's, e.g. "xtls-rprx-vision".
	Flow string `yaml:"flow,omitempty" json:"flow,omitempty"`
	// Plugin and PluginOpts are shadowsocks' SIP003 plugin: "obfs-local" or
	// "v2ray-plugin", with options in the plugin's own "k=v;k=v" form.
	Plugin     string `yaml:"plugin,omitempty" json:"plugin,omitempty"`
	PluginOpts string `yaml:"plugin_opts,omitempty" json:"plugin_opts,omitempty"`

	// TLS turns TLS on for the protocols where it is optional: vmess, vless,
	// socks and http. Trojan, hysteria2, tuic and anytls always use it.
	TLS           bool     `yaml:"tls,omitempty" json:"tls,omitempty"`
	SNI           string   `yaml:"sni,omitempty" json:"sni,omitempty"`
	AllowInsecure bool     `yaml:"allow_insecure,omitempty" json:"allow_insecure,omitempty"`
	ALPN          []string `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	// Fingerprint makes the TLS handshake look like a browser's ("chrome",
	// "firefox", …). Reality needs one and uses chrome when none is named.
	Fingerprint      string `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	RealityPublicKey string `yaml:"reality_public_key,omitempty" json:"reality_public_key,omitempty"`
	RealityShortID   string `yaml:"reality_short_id,omitempty" json:"reality_short_id,omitempty"`

	// Transport is the V2Ray transport under vmess, vless and trojan: "ws",
	// "grpc", "http" or "httpupgrade". Empty is plain TCP.
	Transport   string `yaml:"transport,omitempty" json:"transport,omitempty"`
	Path        string `yaml:"path,omitempty" json:"path,omitempty"`
	Host        string `yaml:"host,omitempty" json:"host,omitempty"`
	ServiceName string `yaml:"service_name,omitempty" json:"service_name,omitempty"`

	// Obfs and ObfsPassword are hysteria2's ("salamander").
	Obfs         string `yaml:"obfs,omitempty" json:"obfs,omitempty"`
	ObfsPassword string `yaml:"obfs_password,omitempty" json:"obfs_password,omitempty"`
	UpMbps       int    `yaml:"up_mbps,omitempty" json:"up_mbps,omitempty"`
	DownMbps     int    `yaml:"down_mbps,omitempty" json:"down_mbps,omitempty"`
	// CongestionControl and UDPRelayMode are tuic's.
	CongestionControl string `yaml:"congestion_control,omitempty" json:"congestion_control,omitempty"`
	UDPRelayMode      string `yaml:"udp_relay_mode,omitempty" json:"udp_relay_mode,omitempty"`

	SubscriptionID string `yaml:"subscription_id,omitempty" json:"subscription_id,omitempty"`
}

// OutboundTag returns the sing-box outbound tag for this node.
func (n CustomNode) OutboundTag() string {
	return nodePrefix + n.ID
}

// EffectiveType is the node's protocol. Nodes saved before there was more
// than one protocol have no type and are all trojan.
func (n CustomNode) EffectiveType() string {
	t := strings.ToLower(n.Type)
	switch t {
	case "":
		return NodeTrojan
	case "ss":
		return NodeShadowsocks
	case "hy2":
		return NodeHysteria2
	case "socks5":
		return NodeSOCKS
	}
	return t
}

// usesQUIC reports whether the node runs over QUIC, which a build without
// -tags with_quic cannot dial.
func (n CustomNode) usesQUIC() bool {
	t := n.EffectiveType()
	return t == NodeHysteria2 || t == NodeTUIC
}

// Unsupported says why this build cannot use the node, or "" when it can.
// Such a node is left out of the engine rather than allowed to stop it from
// starting: one odd entry in a subscription must not take every other node
// down with it.
func (n CustomNode) Unsupported() string {
	switch n.EffectiveType() {
	case NodeTrojan, NodeVMess, NodeVLESS, NodeShadowsocks, NodeAnyTLS, NodeSOCKS, NodeHTTP:
	case NodeHysteria2, NodeTUIC:
		if !quicAvailable {
			return n.EffectiveType() + " needs a client built with -tags with_quic"
		}
	default:
		return "unknown protocol " + n.Type
	}
	if n.RealityPublicKey != "" && !utlsAvailable {
		return "reality needs a client built with -tags with_utls"
	}
	if n.Server == "" || n.Port < 1 || n.Port > 65535 {
		return "no server address"
	}
	return ""
}

// Outbound renders the node as a sing-box outbound.
func (n CustomNode) Outbound() (map[string]any, error) {
	if why := n.Unsupported(); why != "" {
		return nil, errors.New(why)
	}
	typ := n.EffectiveType()
	ob := map[string]any{
		"type":        typ,
		"tag":         n.OutboundTag(),
		"server":      n.Server,
		"server_port": n.Port,
	}
	switch typ {
	case NodeTrojan:
		ob["password"] = n.Password
		ob["tls"] = n.tlsOptions()
		n.addTransport(ob)
	case NodeVMess:
		ob["uuid"] = n.UUID
		ob["security"] = orDefault(n.Method, "auto")
		if n.AlterID > 0 {
			ob["alter_id"] = n.AlterID
		}
		if n.TLS {
			ob["tls"] = n.tlsOptions()
		}
		n.addTransport(ob)
	case NodeVLESS:
		ob["uuid"] = n.UUID
		if n.Flow != "" {
			ob["flow"] = n.Flow
		}
		if n.TLS || n.RealityPublicKey != "" {
			ob["tls"] = n.tlsOptions()
		}
		n.addTransport(ob)
	case NodeShadowsocks:
		ob["method"] = n.Method
		ob["password"] = n.Password
		if n.Plugin != "" {
			ob["plugin"] = n.Plugin
			ob["plugin_opts"] = n.PluginOpts
		}
	case NodeHysteria2:
		ob["password"] = n.Password
		ob["tls"] = n.tlsOptions()
		if n.Obfs != "" {
			ob["obfs"] = map[string]any{"type": n.Obfs, "password": n.ObfsPassword}
		}
		if n.UpMbps > 0 {
			ob["up_mbps"] = n.UpMbps
		}
		if n.DownMbps > 0 {
			ob["down_mbps"] = n.DownMbps
		}
	case NodeTUIC:
		ob["uuid"] = n.UUID
		ob["password"] = n.Password
		ob["tls"] = n.tlsOptions()
		if n.CongestionControl != "" {
			ob["congestion_control"] = n.CongestionControl
		}
		if n.UDPRelayMode != "" {
			ob["udp_relay_mode"] = n.UDPRelayMode
		}
	case NodeAnyTLS:
		ob["password"] = n.Password
		ob["tls"] = n.tlsOptions()
	case NodeSOCKS:
		ob["version"] = "5"
		if n.Username != "" {
			ob["username"] = n.Username
			ob["password"] = n.Password
		}
	case NodeHTTP:
		if n.Username != "" {
			ob["username"] = n.Username
			ob["password"] = n.Password
		}
		if n.TLS {
			ob["tls"] = n.tlsOptions()
		}
	}
	return ob, nil
}

func (n CustomNode) tlsOptions() map[string]any {
	tls := map[string]any{"enabled": true, "server_name": orDefault(n.SNI, n.Server)}
	if n.AllowInsecure {
		tls["insecure"] = true
	}
	alpn := n.ALPN
	if len(alpn) == 0 && n.usesQUIC() {
		alpn = []string{"h3"}
	}
	if len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	fp := n.Fingerprint
	if n.RealityPublicKey != "" {
		// Reality is uTLS underneath; sing-box refuses it without one.
		fp = orDefault(fp, "chrome")
		tls["reality"] = map[string]any{
			"enabled":    true,
			"public_key": n.RealityPublicKey,
			"short_id":   n.RealityShortID,
		}
	}
	// A build without uTLS cannot imitate a browser. That costs a little
	// disguise, not the connection, so the fingerprint is dropped rather than
	// the node.
	if fp != "" && utlsAvailable {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	return tls
}

func (n CustomNode) addTransport(ob map[string]any) {
	switch n.Transport {
	case "ws":
		t := map[string]any{"type": "ws", "path": orDefault(n.Path, "/")}
		if n.Host != "" {
			t["headers"] = map[string]any{"Host": n.Host}
		}
		ob["transport"] = t
	case "grpc":
		ob["transport"] = map[string]any{"type": "grpc", "service_name": n.ServiceName}
	case "http", "h2":
		t := map[string]any{"type": "http", "path": orDefault(n.Path, "/")}
		if n.Host != "" {
			t["host"] = []string{n.Host}
		}
		ob["transport"] = t
	case "httpupgrade":
		t := map[string]any{"type": "httpupgrade", "path": orDefault(n.Path, "/")}
		if n.Host != "" {
			t["host"] = n.Host
		}
		ob["transport"] = t
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// Subscription holds configuration and cached nodes for a remote subscription.
type Subscription struct {
	ID         string `yaml:"id" json:"id"`
	Name       string `yaml:"name" json:"name"`
	URL        string `yaml:"url" json:"url"`
	AutoUpdate bool   `yaml:"auto_update,omitempty" json:"auto_update,omitempty"`
	// UpdateHours is how often an auto-updating subscription is fetched.
	// Zero is daily.
	UpdateHours int    `yaml:"update_hours,omitempty" json:"update_hours,omitempty"`
	UpdatedAt   string `yaml:"updated_at,omitempty" json:"updated_at,omitempty"`
	// Usage is what the provider reported in its subscription-userinfo
	// header: traffic used and allowed, and when the plan ends.
	Usage *SubscriptionUsage `yaml:"usage,omitempty" json:"usage,omitempty"`
	Nodes []CustomNode       `yaml:"nodes,omitempty" json:"nodes,omitempty"`
}

// SubscriptionUsage is a provider's account of a plan. Byte counts; Expire is
// a Unix time, zero when the plan does not end.
type SubscriptionUsage struct {
	Upload   int64 `yaml:"upload,omitempty" json:"upload,omitempty"`
	Download int64 `yaml:"download,omitempty" json:"download,omitempty"`
	Total    int64 `yaml:"total,omitempty" json:"total,omitempty"`
	Expire   int64 `yaml:"expire,omitempty" json:"expire,omitempty"`
}

// UpdateInterval is how long an auto-updating subscription goes between
// fetches.
func (s Subscription) UpdateInterval() time.Duration {
	if s.UpdateHours > 0 {
		return time.Duration(s.UpdateHours) * time.Hour
	}
	return 24 * time.Hour
}

// Due reports whether an auto-updating subscription should be fetched now.
func (s Subscription) Due(now time.Time) bool {
	if !s.AutoUpdate {
		return false
	}
	last, err := time.Parse(time.RFC3339, s.UpdatedAt)
	return err != nil || now.Sub(last) >= s.UpdateInterval()
}

// KeepIDs gives freshly fetched nodes the IDs the same nodes had before, so
// a rule or a selection that names one survives the subscription being
// updated. A node is the same node if it has the same name.
func KeepIDs(fresh, old []CustomNode) {
	byName := make(map[string]string, len(old))
	for _, n := range old {
		byName[n.Name] = n.ID
	}
	used := map[string]bool{}
	for i := range fresh {
		if id, ok := byName[fresh[i].Name]; ok && !used[id] {
			fresh[i].ID = id
		}
		used[fresh[i].ID] = true
	}
}

// GenerateNodeID generates a short random ID for a node.
func GenerateNodeID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())[:8]
	}
	return hex.EncodeToString(b)
}

// ParseNodeURL parses one share link: trojan://, vmess://, vless://, ss://,
// hysteria2:// (or hy2://), tuic://, anytls:// or socks://.
func ParseNodeURL(raw string) (*CustomNode, error) {
	raw = strings.TrimSpace(raw)
	scheme, _, ok := strings.Cut(raw, "://")
	if !ok {
		return nil, errors.New("not a share link")
	}
	var (
		n   *CustomNode
		err error
	)
	switch strings.ToLower(scheme) {
	case "trojan":
		n, err = ParseTrojanURL(raw)
	case "vmess":
		n, err = parseVMessURL(raw)
	case "vless":
		n, err = parseVLESSURL(raw)
	case "ss":
		n, err = parseShadowsocksURL(raw)
	case "hysteria2", "hy2":
		n, err = parseHysteria2URL(raw)
	case "tuic":
		n, err = parseTUICURL(raw)
	case "anytls":
		n, err = parseAnyTLSURL(raw)
	case "socks", "socks5":
		n, err = parseSOCKSURL(raw)
	default:
		return nil, fmt.Errorf("%s:// links are not supported", scheme)
	}
	if err != nil {
		return nil, err
	}
	if n.Name == "" {
		n.Name = net.JoinHostPort(n.Server, strconv.Itoa(n.Port))
	}
	n.ID = GenerateNodeID()
	return n, nil
}

// parsedLink is a share link taken apart the way most of them are written:
// credentials@host:port?query#name.
type parsedLink struct {
	user, pass string
	host       string
	port       int
	q          url.Values
	name       string
}

func parseLink(raw string, defaultPort int) (*parsedLink, error) {
	u, err := url.Parse(firstPort(raw))
	if err != nil {
		return nil, fmt.Errorf("unreadable link: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("the link has no server address")
	}
	// Names are written with + for a space as often as %20, so the fragment
	// is unescaped the way a query is.
	name := u.Fragment
	if unescaped, err := url.QueryUnescape(u.EscapedFragment()); err == nil {
		name = unescaped
	}
	p := &parsedLink{host: host, port: defaultPort, q: u.Query(), name: name}
	if ps := u.Port(); ps != "" {
		port, err := strconv.Atoi(ps)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("the link's port %q is not a port", ps)
		}
		p.port = port
	}
	if u.User != nil {
		p.user = u.User.Username()
		p.pass, _ = u.User.Password()
	}
	return p, nil
}

// firstPort rewrites a port list ("host:443,20000-30000", which hysteria2
// links use for port hopping and url.Parse refuses) to its first port.
func firstPort(raw string) string {
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return raw
	}
	auth, tail := rest, ""
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		auth, tail = rest[:end], rest[end:]
	}
	userinfo, hostport := "", auth
	if at := strings.LastIndex(auth, "@"); at >= 0 {
		userinfo, hostport = auth[:at+1], auth[at+1:]
	}
	colon := strings.LastIndex(hostport, ":")
	if colon < 0 || strings.HasSuffix(hostport, "]") {
		return raw
	}
	ports := hostport[colon+1:]
	if !strings.ContainsAny(ports, ",-") {
		return raw
	}
	first := strings.FieldsFunc(ports, func(r rune) bool { return r == ',' || r == '-' })
	if len(first) == 0 {
		return raw
	}
	return scheme + "://" + userinfo + hostport[:colon+1] + first[0] + tail
}

func (p *parsedLink) first(keys ...string) string {
	for _, k := range keys {
		if v := p.q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func (p *parsedLink) flag(keys ...string) bool {
	v := strings.ToLower(p.first(keys...))
	return v == "1" || v == "true"
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// applyStreamQuery reads the security and transport parameters vless and
// trojan links share.
func (n *CustomNode) applyStreamQuery(p *parsedLink) {
	n.SNI = p.first("sni", "peer", "servername")
	n.AllowInsecure = p.flag("allowInsecure", "insecure", "allow_insecure")
	n.ALPN = splitList(p.first("alpn"))
	n.Fingerprint = p.first("fp")
	switch strings.ToLower(p.first("security")) {
	case "tls", "xtls":
		n.TLS = true
	case "reality":
		n.TLS = true
		n.RealityPublicKey = p.first("pbk")
		n.RealityShortID = p.first("sid")
	}
	switch t := strings.ToLower(p.first("type")); t {
	case "ws", "grpc", "httpupgrade":
		n.Transport = t
	case "http", "h2":
		n.Transport = "http"
	}
	n.Path = p.first("path")
	n.Host = p.first("host")
	n.ServiceName = p.first("serviceName", "service_name")
}

// ParseTrojanURL parses a trojan:// link into a CustomNode.
//
// Format: trojan://password@host:port?sni=...&allowInsecure=1#NodeName
func ParseTrojanURL(raw string) (*CustomNode, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(raw), "trojan://") {
		return nil, errors.New("not a trojan:// URL")
	}
	p, err := parseLink(raw, 443)
	if err != nil {
		return nil, fmt.Errorf("invalid trojan URL: %w", err)
	}
	password := p.user
	if password == "" {
		return nil, errors.New("trojan URL has no password")
	}
	n := &CustomNode{
		ID: GenerateNodeID(), Name: p.name, Type: NodeTrojan,
		Server: p.host, Port: p.port, Password: password,
	}
	n.applyStreamQuery(p)
	if n.SNI == "" {
		n.SNI = p.host
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("%s:%d", p.host, p.port)
	}
	return n, nil
}

func parseVLESSURL(raw string) (*CustomNode, error) {
	p, err := parseLink(raw, 443)
	if err != nil {
		return nil, err
	}
	if p.user == "" {
		return nil, errors.New("vless link has no uuid")
	}
	n := &CustomNode{Name: p.name, Type: NodeVLESS, Server: p.host, Port: p.port, UUID: p.user, Flow: p.first("flow")}
	n.applyStreamQuery(p)
	return n, nil
}

// vmessLink is the JSON a vmess:// link carries, base64 encoded. Clients
// disagree about whether numbers are numbers or strings, so they are read as
// either.
type vmessLink struct {
	PS   string      `json:"ps"`
	Add  string      `json:"add"`
	Port json.Number `json:"port"`
	ID   string      `json:"id"`
	Aid  json.Number `json:"aid"`
	Scy  string      `json:"scy"`
	Net  string      `json:"net"`
	Type string      `json:"type"`
	Host string      `json:"host"`
	Path string      `json:"path"`
	TLS  string      `json:"tls"`
	SNI  string      `json:"sni"`
	ALPN string      `json:"alpn"`
	FP   string      `json:"fp"`
}

func (v *vmessLink) UnmarshalJSON(b []byte) error {
	// Numbers arrive both as 443 and as "443"; json.Number takes only the
	// first, so strings are unquoted into it by hand.
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	str := func(k string) string {
		switch x := m[k].(type) {
		case string:
			return x
		case float64:
			return strconv.FormatFloat(x, 'f', -1, 64)
		}
		return ""
	}
	*v = vmessLink{
		PS: str("ps"), Add: str("add"), Port: json.Number(str("port")), ID: str("id"),
		Aid: json.Number(str("aid")), Scy: str("scy"), Net: str("net"), Type: str("type"),
		Host: str("host"), Path: str("path"), TLS: str("tls"), SNI: str("sni"),
		ALPN: str("alpn"), FP: str("fp"),
	}
	return nil
}

func parseVMessURL(raw string) (*CustomNode, error) {
	body := strings.TrimPrefix(strings.TrimPrefix(raw, "vmess://"), "VMESS://")
	decoded, err := tryBase64Decode(body)
	if err != nil {
		return nil, errors.New("vmess link is not base64")
	}
	var v vmessLink
	if err := json.Unmarshal(decoded, &v); err != nil {
		return nil, fmt.Errorf("vmess link does not hold JSON: %w", err)
	}
	port, _ := v.Port.Int64()
	aid, _ := v.Aid.Int64()
	if v.Add == "" || port <= 0 || port > 65535 || v.ID == "" {
		return nil, errors.New("vmess link is missing its server, port or id")
	}
	n := &CustomNode{
		Name: v.PS, Type: NodeVMess, Server: v.Add, Port: int(port),
		UUID: v.ID, AlterID: int(aid), Method: v.Scy,
		TLS: strings.EqualFold(v.TLS, "tls"), SNI: v.SNI, ALPN: splitList(v.ALPN), Fingerprint: v.FP,
		Path: v.Path, Host: v.Host,
	}
	switch strings.ToLower(v.Net) {
	case "ws", "grpc", "httpupgrade":
		n.Transport = strings.ToLower(v.Net)
	case "h2", "http":
		n.Transport = "http"
	case "tcp", "":
		if v.Type == "http" {
			n.Transport = "http"
		}
	}
	if n.Transport == "grpc" {
		n.ServiceName, n.Path = v.Path, ""
	}
	return n, nil
}

// parseShadowsocksURL reads both forms in use: SIP002
// (ss://base64(method:password)@host:port?plugin=…#name, where the userinfo
// may also be plain) and the older ss://base64(method:password@host:port)#name.
func parseShadowsocksURL(raw string) (*CustomNode, error) {
	body := raw[len("ss://"):]
	name := ""
	if i := strings.Index(body, "#"); i >= 0 {
		name, _ = url.PathUnescape(body[i+1:])
		body = body[:i]
	}
	if !strings.Contains(body, "@") {
		decoded, err := tryBase64Decode(strings.SplitN(body, "?", 2)[0])
		if err != nil {
			return nil, errors.New("shadowsocks link is not readable")
		}
		body = string(decoded)
	}
	at := strings.LastIndex(body, "@")
	if at < 0 {
		return nil, errors.New("shadowsocks link has no server")
	}
	userinfo, hostpart := body[:at], body[at+1:]
	if unescaped, err := url.PathUnescape(userinfo); err == nil {
		userinfo = unescaped
	}
	if !strings.Contains(userinfo, ":") {
		decoded, err := tryBase64Decode(userinfo)
		if err != nil {
			return nil, errors.New("shadowsocks link has unreadable credentials")
		}
		userinfo = string(decoded)
	}
	method, password, ok := strings.Cut(userinfo, ":")
	if !ok || method == "" {
		return nil, errors.New("shadowsocks link has no cipher")
	}
	p, err := parseLink("ss://x@"+hostpart, 0)
	if err != nil {
		return nil, err
	}
	if p.port == 0 {
		return nil, errors.New("shadowsocks link has no port")
	}
	n := &CustomNode{Name: name, Type: NodeShadowsocks, Server: p.host, Port: p.port, Method: method, Password: password}
	if plugin := p.q.Get("plugin"); plugin != "" {
		n.Plugin, n.PluginOpts, _ = strings.Cut(plugin, ";")
		if n.Plugin == "simple-obfs" {
			n.Plugin = "obfs-local"
		}
	}
	return n, nil
}

func parseHysteria2URL(raw string) (*CustomNode, error) {
	p, err := parseLink(raw, 443)
	if err != nil {
		return nil, err
	}
	password := p.user
	if p.pass != "" {
		password = p.user + ":" + p.pass
	}
	n := &CustomNode{
		Name: p.name, Type: NodeHysteria2, Server: p.host, Port: p.port, Password: password,
		SNI: p.first("sni", "peer"), AllowInsecure: p.flag("insecure", "allowInsecure"),
		ALPN: splitList(p.first("alpn")), Obfs: p.first("obfs"), ObfsPassword: p.first("obfs-password", "obfs_password"),
	}
	n.UpMbps, _ = strconv.Atoi(p.first("upmbps", "up"))
	n.DownMbps, _ = strconv.Atoi(p.first("downmbps", "down"))
	return n, nil
}

func parseTUICURL(raw string) (*CustomNode, error) {
	p, err := parseLink(raw, 443)
	if err != nil {
		return nil, err
	}
	if p.user == "" {
		return nil, errors.New("tuic link has no uuid")
	}
	return &CustomNode{
		Name: p.name, Type: NodeTUIC, Server: p.host, Port: p.port, UUID: p.user, Password: p.pass,
		SNI: p.first("sni"), AllowInsecure: p.flag("allow_insecure", "insecure", "allowInsecure"),
		ALPN: splitList(p.first("alpn")), CongestionControl: p.first("congestion_control"),
		UDPRelayMode: p.first("udp_relay_mode"),
	}, nil
}

func parseAnyTLSURL(raw string) (*CustomNode, error) {
	p, err := parseLink(raw, 443)
	if err != nil {
		return nil, err
	}
	return &CustomNode{
		Name: p.name, Type: NodeAnyTLS, Server: p.host, Port: p.port, Password: p.user,
		SNI: p.first("sni", "peer"), AllowInsecure: p.flag("insecure", "allowInsecure"),
		Fingerprint: p.first("fp"),
	}, nil
}

func parseSOCKSURL(raw string) (*CustomNode, error) {
	p, err := parseLink(raw, 1080)
	if err != nil {
		return nil, err
	}
	user, pass := p.user, p.pass
	// Some clients write the credentials as one base64 "user:pass".
	if user != "" && pass == "" {
		if decoded, err := tryBase64Decode(user); err == nil && strings.Contains(string(decoded), ":") {
			user, pass, _ = strings.Cut(string(decoded), ":")
		}
	}
	return &CustomNode{Name: p.name, Type: NodeSOCKS, Server: p.host, Port: p.port, Username: user, Password: pass}, nil
}

// ParseSubscription parses subscription content: a Clash configuration, or a
// list of share links, base64 encoded or not.
func ParseSubscription(data []byte) ([]CustomNode, error) {
	str := strings.TrimSpace(string(data))
	if str == "" {
		return nil, errors.New("subscription content is empty")
	}

	if strings.Contains(str, "proxies:") {
		nodes, err := parseClashYAML(data)
		if err == nil && len(nodes) > 0 {
			return nodes, nil
		}
	}

	if decoded, err := tryBase64Decode(str); err == nil && len(decoded) > 0 && strings.Contains(string(decoded), "://") {
		str = string(decoded)
	}

	var nodes []CustomNode
	for _, line := range strings.Split(str, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if node, err := ParseNodeURL(line); err == nil {
			nodes = append(nodes, *node)
		}
	}

	if len(nodes) == 0 {
		return nil, errors.New("no usable nodes found in the subscription")
	}
	return nodes, nil
}

func tryBase64Decode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}

// parseClashYAML reads the proxies of a Clash configuration. Entries are read
// as loose maps rather than a struct: providers write ports as numbers or
// strings and nest options several ways, and one entry that does not fit a
// struct would otherwise lose the whole subscription.
func parseClashYAML(data []byte) ([]CustomNode, error) {
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var nodes []CustomNode
	for _, p := range doc.Proxies {
		if n, ok := clashNode(clashMap(p)); ok {
			n.ID = GenerateNodeID()
			nodes = append(nodes, n)
		}
	}
	return nodes, nil
}

type clashMap map[string]any

func (m clashMap) str(keys ...string) string {
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case int:
			return strconv.Itoa(v)
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
	}
	return ""
}

func (m clashMap) num(keys ...string) int {
	s := m.str(keys...)
	// Bandwidth is written "100 Mbps" as often as 100.
	s = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(s), "mbps"))
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func (m clashMap) flag(key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	}
	return false
}

func (m clashMap) sub(key string) clashMap {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return clashMap{}
}

func (m clashMap) list(key string) []string {
	switch v := m[key].(type) {
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return splitList(v)
	}
	return nil
}

func clashNode(m clashMap) (CustomNode, bool) {
	n := CustomNode{
		Name: m.str("name"), Server: m.str("server"), Port: m.num("port"),
		SNI: m.str("sni", "servername"), AllowInsecure: m.flag("skip-cert-verify"),
		ALPN: m.list("alpn"), Fingerprint: m.str("client-fingerprint"),
	}
	switch strings.ToLower(m.str("type")) {
	case "trojan":
		n.Type, n.Password = NodeTrojan, m.str("password")
	case "vmess":
		n.Type, n.UUID, n.AlterID, n.Method, n.TLS = NodeVMess, m.str("uuid"), m.num("alterId"), m.str("cipher"), m.flag("tls")
	case "vless":
		n.Type, n.UUID, n.Flow, n.TLS = NodeVLESS, m.str("uuid"), m.str("flow"), m.flag("tls")
	case "ss":
		n.Type, n.Method, n.Password = NodeShadowsocks, m.str("cipher"), m.str("password")
		opts := m.sub("plugin-opts")
		switch m.str("plugin") {
		case "obfs":
			n.Plugin = "obfs-local"
			n.PluginOpts = "obfs=" + opts.str("mode")
			if h := opts.str("host"); h != "" {
				n.PluginOpts += ";obfs-host=" + h
			}
		case "v2ray-plugin":
			n.Plugin = "v2ray-plugin"
			parts := []string{"mode=" + orDefault(opts.str("mode"), "websocket")}
			if h := opts.str("host"); h != "" {
				parts = append(parts, "host="+h)
			}
			if p := opts.str("path"); p != "" {
				parts = append(parts, "path="+p)
			}
			if opts.flag("tls") {
				parts = append(parts, "tls")
			}
			n.PluginOpts = strings.Join(parts, ";")
		}
	case "hysteria2":
		n.Type, n.Password = NodeHysteria2, m.str("password", "auth")
		n.Obfs, n.ObfsPassword = m.str("obfs"), m.str("obfs-password")
		n.UpMbps, n.DownMbps = m.num("up"), m.num("down")
	case "tuic":
		n.Type, n.UUID, n.Password = NodeTUIC, m.str("uuid"), m.str("password")
		n.CongestionControl = m.str("congestion-controller")
		n.UDPRelayMode = m.str("udp-relay-mode")
	case "anytls":
		n.Type, n.Password = NodeAnyTLS, m.str("password")
	case "socks5":
		n.Type, n.Username, n.Password = NodeSOCKS, m.str("username"), m.str("password")
	case "http":
		n.Type, n.Username, n.Password, n.TLS = NodeHTTP, m.str("username"), m.str("password"), m.flag("tls")
	default:
		return n, false
	}

	switch network := m.str("network"); network {
	case "ws":
		n.Transport = "ws"
		o := m.sub("ws-opts")
		n.Path = o.str("path")
		n.Host = o.sub("headers").str("Host", "host")
	case "grpc":
		n.Transport = "grpc"
		n.ServiceName = m.sub("grpc-opts").str("grpc-service-name")
	case "h2", "http":
		n.Transport = "http"
		o := m.sub(network + "-opts")
		n.Path = o.str("path")
		if hosts := o.list("host"); len(hosts) > 0 {
			n.Host = hosts[0]
		}
	}
	if r := m.sub("reality-opts"); r.str("public-key") != "" {
		n.TLS = true
		n.RealityPublicKey, n.RealityShortID = r.str("public-key"), r.str("short-id")
	}
	if n.Name == "" {
		n.Name = net.JoinHostPort(n.Server, strconv.Itoa(n.Port))
	}
	if n.Server == "" || n.Port <= 0 || n.Port > 65535 {
		return n, false
	}
	return n, true
}

// FetchedSubscription is what a subscription download produced.
type FetchedSubscription struct {
	Nodes []CustomNode
	Usage *SubscriptionUsage
}

// FetchSubscription downloads and parses a subscription from the provided URL.
func FetchSubscription(ctx context.Context, subURL string) (*FetchedSubscription, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subURL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid subscription URL: %w", err)
	}
	// Providers pick a format by user agent. Naming Clash gets the richest
	// one, and the one every provider serves.
	req.Header.Set("User-Agent", "clash.meta vpn-gateway/1.0 (sing-box)")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download subscription failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("subscription returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("read subscription body: %w", err)
	}
	nodes, err := ParseSubscription(body)
	if err != nil {
		return nil, err
	}
	return &FetchedSubscription{Nodes: nodes, Usage: parseUserinfo(resp.Header.Get("Subscription-Userinfo"))}, nil
}

// parseUserinfo reads "upload=1; download=2; total=3; expire=4".
func parseUserinfo(h string) *SubscriptionUsage {
	if h == "" {
		return nil
	}
	var u SubscriptionUsage
	for _, part := range strings.Split(h, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			continue
		}
		switch strings.TrimSpace(k) {
		case "upload":
			u.Upload = int64(n)
		case "download":
			u.Download = int64(n)
		case "total":
			u.Total = int64(n)
		case "expire":
			u.Expire = int64(n)
		}
	}
	if u == (SubscriptionUsage{}) {
		return nil
	}
	return &u
}
