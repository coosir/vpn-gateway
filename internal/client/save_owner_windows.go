//go:build windows

package client

import "os"

// preserveOwner does nothing on Windows: the service runs under an account of
// its own and file ownership is not what decides who may write there.
func preserveOwner(*os.File, string) error { return nil }
