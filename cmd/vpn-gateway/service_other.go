//go:build !windows

package main

func isWindowsService() bool { return false }
func runWindowsService(configPath, logLevel string) error { return nil }
