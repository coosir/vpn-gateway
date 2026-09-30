package inode

import (
	"bytes"
	"context"
	"crypto/des"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// profileKey is the DES key H3C's client encrypts a saved password with. It is
// a constant compiled into libInodeUtility.so (DES_SECRET_KEY), the same on
// every installation, so it protects nothing: it is here because the service
// will not read a password stored any other way.
const profileKey = "liuan814"

// encryptPassword stores a password the way the client's own utl_encrpt does:
// DES in ECB mode with PKCS#5 padding, then base64.
//
// Checked against the vendor library itself, called from a container: see the
// vectors in the tests.
func encryptPassword(password string) string {
	block, err := des.NewCipher([]byte(profileKey))
	if err != nil {
		panic(err) // the key is a constant of the right length
	}
	bs := block.BlockSize()
	pad := bs - len(password)%bs
	buf := append([]byte(password), bytes.Repeat([]byte{byte(pad)}, pad)...)
	out := make([]byte, len(buf))
	for i := 0; i < len(buf); i += bs {
		block.Encrypt(out[i:i+bs], buf[i:i+bs])
	}
	return base64.StdEncoding.EncodeToString(out)
}

// profile is one saved SSL VPN connection, as the client's own window writes
// it to clientfiles/7000/<name>.icnf.
//
// AUTO_AUTHEN is what makes this work without the window at all: on start,
// AuthenMngService reads every profile in that directory and dials the ones
// marked for automatic login, with the password saved alongside.
type profile struct {
	Name string
	Host string
	// Addr is Host resolved. The service does not resolve anything itself:
	// the window does, and saves the address alongside the name. With no
	// address the service connects to 0.0.0.0.
	Addr     net.IP
	Port     int
	Username string
	Password string
	// Domain is the authentication domain the login form offers, if any.
	Domain string
}

// render writes the profile in the window's format: KEY=value, each line
// ended by a tab and a newline, in the window's order. The service looks keys
// up by name, but nothing is gained by departing from what it is used to.
func (p profile) render() []byte {
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "%s=%s\t\n", k, v) }
	line("CONNECT_NAME", p.Name)
	line("COIDENT", "1")
	line("USER_NAME", p.Username)
	line("SAVE_PASSWORD", "1")
	line("PASSWORD", encryptPassword(p.Password))
	line("MSGAUTH", "0")
	line("RSA", "0")
	line("AUTO_AUTHEN", "1")
	line("ONLINE_STATUS", "0")
	line("CHOOSECERT", "0")
	line("REAUTHTIMES", "0")
	line("REAUTHINTERVAL", "0")
	line("AUTHTYPE", "0")
	line("AUTHNAME", "")
	// The address twice, as the window saves it: an in_addr's four bytes
	// read as one little-endian number, and dotted. Either alone is enough
	// for the service to connect.
	line("REMOTEIP", strconv.FormatUint(uint64(remoteIP(p.Addr)), 10))
	line("REMOTEPOTR", strconv.Itoa(p.Port)) // sic: the service's spelling
	line("DOMAINID", "0")
	line("DOMAINNAME", p.Domain)
	line("AUTHMODE", "0")
	line("STRREMOTEIP", dotted(p.Addr))
	line("STRREMOTEHOST", p.Host)
	line("ROOTFILE", "")
	line("CLIENTFILE", "")
	line("CLIENTCERTPWD", "")
	// Read by the service and logged as an error when absent, though an
	// empty value is all a password login needs.
	line("CERTISSUER", "")
	line("CERTHASH", "")
	return []byte(b.String())
}

func remoteIP(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(v4)
}

func dotted(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ""
}

// resolveGateway finds the IPv4 address the service will connect to. It runs
// before every dial, so a gateway whose address moves is followed.
func resolveGateway(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return nil, fmt.Errorf("gateway %s is IPv6, which the iNode client cannot reach", host)
		}
		return ip, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("resolve gateway %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("gateway %s has no IPv4 address", host)
	}
	return ips[0], nil
}

// splitServer takes the gateway as people tend to write it -- a bare name,
// name:port, or the address they open in a browser -- and returns the host and
// port the service wants. port is used when the server names none.
func splitServer(server string, port int) (string, int, error) {
	s := strings.TrimSpace(server)
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", 0, fmt.Errorf("server %q is not an address: %w", server, err)
		}
		s = u.Host
	}
	s = strings.TrimSuffix(s, "/")
	host := s
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return "", 0, fmt.Errorf("server %q has no usable port", server)
		}
		host, port = h, n
	}
	if host == "" {
		return "", 0, fmt.Errorf("server %q names no host", server)
	}
	return host, port, nil
}
