//go:build packed

package clientbin

import _ "embed"

// packed is the compressed client executable. The build writes client.bin
// before compiling with this tag; see the windows target in the Makefile.
//
//go:embed client.bin
var packed []byte
