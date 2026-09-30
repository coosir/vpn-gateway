package inode

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The vectors are what utl_encrpt in the client's own libInodeUtility.so
// returned for these inputs, called from a container. If they stop matching,
// the service reads a password that is not the one configured, and every dial
// is a failed login counted against the account.
func TestPasswordIsEncryptedAsTheClientDoes(t *testing.T) {
	for in, want := range map[string]string{
		"testpass":         "ZGNtF0HkeK9z49ySlWKaPQ==",
		"P@ssw0rd!2345678": "23bNpBrd9bss4YCXpITCIXPj3JKVYpo9",
	} {
		if got := encryptPassword(in); got != want {
			t.Errorf("encryptPassword(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProfileIsWhatTheServiceDials(t *testing.T) {
	body := string(profile{
		Name: "vpn-gateway", Host: "vpn.corp.example", Addr: net.ParseIP("192.168.97.2"),
		Port: 4433, Username: "alice", Password: "testpass", Domain: "staff",
	}.render())

	for _, want := range []string{
		"CONNECT_NAME=vpn-gateway\t\n",
		// The service connects to this, and never resolves the name. This
		// value reached a gateway at 192.168.97.2; the same address read
		// big-endian (3232260354) did not.
		"REMOTEIP=39954624\t\n",
		"STRREMOTEIP=192.168.97.2\t\n",
		"USER_NAME=alice\t\n",
		"SAVE_PASSWORD=1\t\n",
		"PASSWORD=ZGNtF0HkeK9z49ySlWKaPQ==\t\n",
		// Without this the service loads the profile and waits for a window
		// to be told to dial it.
		"AUTO_AUTHEN=1\t\n",
		"STRREMOTEHOST=vpn.corp.example\t\n",
		"REMOTEPOTR=4433\t\n",
		"DOMAINNAME=staff\t\n",
		"CERTISSUER=\t\n",
		"CERTHASH=\t\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("profile is missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "testpass") {
		t.Error("the password was written in the clear")
	}
}

func TestGatewayGivenAsAnAddressIsNotLookedUp(t *testing.T) {
	ip, err := resolveGateway(context.Background(), "10.1.2.3")
	if err != nil || !ip.Equal(net.ParseIP("10.1.2.3")) {
		t.Errorf("resolveGateway(10.1.2.3) = %v, %v", ip, err)
	}
	if _, err := resolveGateway(context.Background(), "2001:db8::1"); err == nil {
		t.Error("an IPv6 gateway was accepted; the service only takes IPv4")
	}
}

// Every profile in the directory is dialled, so one left over from an earlier
// configuration would log in too.
func TestOnlyOneProfileIsLeft(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "old.icnf")
	if err := os.WriteFile(stale, []byte("CONNECT_NAME=old\t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeProfile(dir, profile{Name: "vpn-gateway", Host: "h", Port: 443, Username: "u"}); err != nil {
		t.Fatal(err)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*.icnf"))
	if len(left) != 1 || filepath.Base(left[0]) != "vpn-gateway.icnf" {
		t.Errorf("profiles left: %v", left)
	}
	info, err := os.Stat(left[0])
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("profile mode %v; it holds the password", info.Mode().Perm())
	}
}

func TestServerIsAcceptedAsPeopleWriteIt(t *testing.T) {
	for in, want := range map[string]struct {
		host string
		port int
	}{
		"vpn.corp.example":               {"vpn.corp.example", 443},
		"vpn.corp.example:4433":          {"vpn.corp.example", 4433},
		"https://vpn.corp.example/":      {"vpn.corp.example", 443},
		"https://vpn.corp.example:8443/": {"vpn.corp.example", 8443},
		" 10.1.2.3:10443 ":               {"10.1.2.3", 10443},
	} {
		host, port, err := splitServer(in, 443)
		if err != nil || host != want.host || port != want.port {
			t.Errorf("splitServer(%q) = %q, %d, %v; want %q, %d", in, host, port, err, want.host, want.port)
		}
	}
	for _, bad := range []string{"", "vpn.corp.example:0", "vpn.corp.example:http"} {
		if _, _, err := splitServer(bad, 443); err == nil {
			t.Errorf("splitServer(%q) accepted", bad)
		}
	}
}

// Lines as libiNodeSslvpnPt.so writes them to its log.
func TestServiceLogIsRead(t *testing.T) {
	for line, want := range map[string]kind{
		"[2026-09-30 07:03:24] [WARNING] [0x7f] CSslClient::conn2Remote SSLVPN Tunnel Build SUCCESSFULLY.":                    lineBuilt,
		"[2026-09-30 07:03:24] [WARNING] [0x7f] CSslClient::conn2RemoteReuseIP VPN REBUILD SUCCESSFULLY.":                     lineBuilt,
		"[2026-09-30 07:03:24] [ERROR] [0x7f] CHttpsAuth::handleAuthRespMsg the response has error information: bad password": lineRejected,
		"[2026-09-30 07:03:24] [ERROR] [0x7f] CHttpsAuth::hasErrorTitle the http response has error title: locked":            lineRejected,
		"[2026-09-30 07:03:24] [WARNING] [0x7f] CSslVpnMgr::startConn Failed to call queryVpnPara().status = 0.":              lineFailed,
		// Seen on every start, working or not.
		"[2026-09-30 07:03:24] [ERROR] [0x7f] CVirNIC::EnableVirNIC if tun0 op 1":        lineOther,
		"[2026-09-30 07:03:24] [WARNING] [0x7f] CSslVpnMgr::startConn start connection.": lineOther,
		"modprobe: FATAL: Module tun not found in directory /lib/modules/6.1":            lineOther,
	} {
		if got := lineKind(line); got != want {
			t.Errorf("lineKind(%q) = %d, want %d", line, got, want)
		}
	}
}
