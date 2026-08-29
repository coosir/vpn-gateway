package clientbox

import "golang.org/x/net/proxy"

// socks5Dialer builds a context-aware dialer for a local SOCKS5 port.
func socks5Dialer(addr string) (proxy.ContextDialer, error) {
	d, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, errNoContextDialer
	}
	return cd, nil
}

type dialerError string

func (e dialerError) Error() string { return string(e) }

const errNoContextDialer = dialerError("clientbox: the SOCKS5 dialer does not support contexts")
