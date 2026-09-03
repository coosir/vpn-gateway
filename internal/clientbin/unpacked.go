//go:build !packed

package clientbin

// packed is empty in a build that was not given a client executable to carry.
// Nothing depends on having one: it is asked for and, where it is missing,
// the executable beside the application is used instead.
var packed []byte
