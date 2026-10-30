//go:build !with_utls

package client

// utlsAvailable reports whether this build can imitate a browser's TLS
// handshake, which reality nodes require. It needs -tags with_utls, which the
// shipped builds have.
const utlsAvailable = false
