package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/internal/version"
)

// TunnelStore keeps the tunnels the admin page edits.
type TunnelStore interface {
	PutTunnel(server.TunnelConfig) error
	DeleteTunnel(name string) error
}

// SetTunnelStore turns on editing tunnels through the API. Without one the
// tunnels can be read but not changed.
func (s *Server) SetTunnelStore(st TunnelStore, portBase int) {
	s.store = st
	s.portBase = portBase
}

// Unchanged stands in for a secret the admin page is not shown. Sent back as
// it was, it keeps what is stored; anything else replaces it.
const Unchanged = "(unchanged)"

// isSecretKey reports whether a provider setting holds a credential, which is
// handed to the admin page as Unchanged rather than in the clear.
func isSecretKey(k string) bool {
	k = strings.ToLower(k)
	for _, w := range []string{"secret", "password", "token", "cookie"} {
		if strings.Contains(k, w) {
			return true
		}
	}
	return false
}

// redact hides a tunnel's credentials.
func redact(t server.TunnelConfig) server.TunnelConfig {
	if t.Password != "" {
		t.Password = Unchanged
	}
	if len(t.Extra) > 0 {
		extra := make(map[string]string, len(t.Extra))
		for k, v := range t.Extra {
			if v != "" && isSecretKey(k) {
				v = Unchanged
			}
			extra[k] = v
		}
		t.Extra = extra
	}
	return t
}

// unredact puts back whatever the page left as Unchanged.
func unredact(t, old server.TunnelConfig) server.TunnelConfig {
	if t.Password == Unchanged {
		t.Password = old.Password
	}
	for k, v := range t.Extra {
		if v == Unchanged {
			if prev, ok := old.Extra[k]; ok {
				t.Extra[k] = prev
			} else {
				delete(t.Extra, k)
			}
		}
	}
	return t
}

// Provider is one kind of tunnel the admin page offers, with what a new one
// of that kind usually needs.
type Provider struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Image       string   `json:"image,omitempty"`
	CapAdd      []string `json:"cap_add,omitempty"`
	Devices     []string `json:"devices,omitempty"`
	NoContainer bool     `json:"no_container,omitempty"`
}

func openconnect(name, label string) Provider {
	return Provider{Name: name, Label: label, Image: "coosir/vg-openconnect:latest",
		CapAdd: []string{"NET_ADMIN"}, Devices: []string{"/dev/net/tun"}}
}

// providers is what config.example.yaml documents, in the order a person is
// likely to look for them.
var providers = []Provider{
	{Name: "direct", Label: "服务器本机网络 (direct)", NoContainer: true},
	{Name: "trojan", Label: "上游 Trojan 节点", NoContainer: true},
	openconnect("anyconnect", "Cisco AnyConnect"),
	openconnect("fortinet", "Fortinet"),
	openconnect("gp", "Palo Alto GlobalProtect"),
	openconnect("pulse", "Pulse Secure"),
	openconnect("f5", "F5"),
	openconnect("array", "Array Networks"),
	{Name: "easyconnect", Label: "深信服 EasyConnect", Image: "coosir/vg-sangfor:latest"},
	{Name: "atrust", Label: "深信服 aTrust", Image: "coosir/vg-sangfor:latest"},
	{Name: "inode", Label: "H3C iNode", Image: "coosir/vg-inode:latest",
		CapAdd: []string{"NET_ADMIN"}, Devices: []string{"/dev/net/tun"}},
	{Name: "mock", Label: "Mock（测试用）", Image: "coosir/vg-mock:latest"},
}

func (s *Server) getAdminInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":   version.Full(),
		"editable":  s.store != nil,
		"providers": providers,
		"unchanged": Unchanged,
	})
}

func (s *Server) listTunnelConfigs(w http.ResponseWriter, r *http.Request) {
	out := []server.TunnelConfig{}
	for _, t := range s.mgr.Configs() {
		out = append(out, redact(t))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) postTunnelConfig(w http.ResponseWriter, r *http.Request) {
	tc, ok := s.decodeTunnel(w, r)
	if !ok {
		return
	}
	if _, exists := s.mgr.Config(tc.Name); exists {
		writeErr(w, http.StatusConflict, fmt.Sprintf("a tunnel named %q already exists", tc.Name))
		return
	}
	if tc.Password == Unchanged {
		tc.Password = ""
	}
	s.saveTunnel(w, r, tc, http.StatusCreated)
}

func (s *Server) putTunnelConfig(w http.ResponseWriter, r *http.Request) {
	tc, ok := s.decodeTunnel(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if tc.Name != name {
		// The name is the container, the network, the secrets and every
		// client's routing rule; changing it is a new tunnel.
		writeErr(w, http.StatusBadRequest, "a tunnel cannot be renamed; add a new one and delete this one")
		return
	}
	old, exists := s.mgr.Config(name)
	if !exists {
		writeErr(w, http.StatusNotFound, "no such tunnel")
		return
	}
	tc = unredact(tc, old)
	// A tunnel's ports are its own for as long as it exists. Asking for new
	// ones is allowed; leaving them out keeps what it had.
	if tc.DataPort == 0 && tc.ControlPort == 0 {
		tc.DataPort, tc.ControlPort = old.DataPort, old.ControlPort
	}
	s.saveTunnel(w, r, tc, http.StatusOK)
}

func (s *Server) deleteTunnelConfig(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeErr(w, http.StatusNotImplemented, "tunnels are not editable on this server")
		return
	}
	name := r.PathValue("name")
	if _, exists := s.mgr.Config(name); !exists {
		writeErr(w, http.StatusNotFound, "no such tunnel")
		return
	}
	if err := s.store.DeleteTunnel(name); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.mgr.Remove(name); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.usersMgr != nil {
		if err := s.usersMgr.ForgetTunnel(name); err != nil {
			s.log.Warn("could not take the deleted tunnel out of users' access", "tunnel", name, "error", err)
		}
	}
	s.log.Info("tunnel deleted from the admin page", "tunnel", name, "by", userOf(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) decodeTunnel(w http.ResponseWriter, r *http.Request) (server.TunnelConfig, bool) {
	var tc server.TunnelConfig
	if s.store == nil {
		writeErr(w, http.StatusNotImplemented, "tunnels are not editable on this server")
		return tc, false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tc); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed tunnel: "+err.Error())
		return tc, false
	}
	tc.Name = strings.TrimSpace(tc.Name)
	tc.Provider = strings.TrimSpace(tc.Provider)
	tc.Image = strings.TrimSpace(tc.Image)
	tc.Server = strings.TrimSpace(tc.Server)
	for k, v := range tc.Extra {
		if strings.TrimSpace(k) == "" || v == "" {
			delete(tc.Extra, k)
		}
	}
	return tc, true
}

// saveTunnel checks a tunnel against the others, keeps it, and hands it to the
// manager, which puts it into effect at once.
func (s *Server) saveTunnel(w http.ResponseWriter, r *http.Request, tc server.TunnelConfig, code int) {
	others := s.mgr.Configs()
	server.AllocatePorts(&tc, others, s.portBase)
	var errs []error
	if err := tc.Validate(); err != nil {
		errs = append(errs, err)
	}
	if p := server.PortConflict(tc, others); p != 0 {
		errs = append(errs, fmt.Errorf("port %d is already used by another tunnel", p))
	}
	if !tc.Disabled {
		if _, err := tc.ResolvePassword(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Kept first: what is in the database is what the next start runs, so a
	// tunnel that is running and not saved is the one to avoid.
	if err := s.store.PutTunnel(tc); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.mgr.Put(tc); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.log.Info("tunnel saved from the admin page", "tunnel", tc.Name, "by", userOf(r))
	writeJSON(w, code, redact(tc))
}

func userOf(r *http.Request) string {
	u, _ := r.Context().Value(userContextKey).(string)
	return u
}
