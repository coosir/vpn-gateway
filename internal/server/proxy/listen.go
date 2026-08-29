package proxy

import (
	"fmt"
	"net"
	"strconv"
)

// splitListen turns ":443" or "10.0.0.1:443" into the host and port fields
// sing-box expects. An empty host becomes "::", which listens on every
// address.
func splitListen(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("proxy: %q is not a host:port address: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("proxy: %q does not contain a valid port", addr)
	}
	if host == "" {
		host = "::"
	}
	return host, port, nil
}
