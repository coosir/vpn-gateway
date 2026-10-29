package store

import (
	"testing"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/internal/server/users"
)

func TestSeedOnceThenEditByRow(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if seeded, err := st.Seeded(); err != nil || seeded {
		t.Fatalf("a new database says seeded=%v, %v", seeded, err)
	}
	err = st.Seed(
		[]server.TunnelConfig{
			{Name: "office", Provider: "anyconnect", Image: "img", Password: "pw", DataPort: 21000, ControlPort: 21001,
				Extra: map[string]string{"routes": "10.0.0.0/8"}},
			{Name: "lan", Provider: "direct"},
		},
		[]users.User{{Username: "alice", PasswordHash: "h", IsAdmin: true}},
	)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()

	// Reopened, as a restart would: the schema is not applied twice, and
	// what was imported is all there.
	st, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if seeded, _ := st.Seeded(); !seeded {
		t.Fatal("seeding did not stick")
	}
	got, err := st.Tunnels()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "lan" || got[1].Name != "office" {
		t.Fatalf("tunnels = %+v", got)
	}
	o := got[1]
	if o.Password != "pw" || o.DataPort != 21000 || o.Extra["routes"] != "10.0.0.0/8" {
		t.Errorf("office came back as %+v", o)
	}

	o.Server = "vpn.example"
	if err := st.PutTunnel(o); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteTunnel("lan"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteTunnel("lan"); err != ErrNotFound {
		t.Errorf("deleting twice: %v", err)
	}
	got, _ = st.Tunnels()
	if len(got) != 1 || got[0].Server != "vpn.example" {
		t.Fatalf("after edits: %+v", got)
	}

	us, err := st.LoadUsers()
	if err != nil || len(us) != 1 || us[0].Username != "alice" || !us[0].IsAdmin || us[0].CreatedAt.IsZero() {
		t.Fatalf("users = %+v, %v", us, err)
	}
	if us[0].Restricted || len(us[0].Tunnels) != 0 {
		t.Errorf("a user nobody restricted came back restricted: %+v", us[0])
	}
	if err := st.SaveUsers([]users.User{{Username: "bob", PasswordHash: "x", Restricted: true, Tunnels: []string{"lab", "office"}}}); err != nil {
		t.Fatal(err)
	}
	us, _ = st.LoadUsers()
	if len(us) != 1 || us[0].Username != "bob" || !us[0].Restricted || len(us[0].Tunnels) != 2 || us[0].Tunnels[1] != "office" {
		t.Fatalf("users after save = %+v", us)
	}
}
