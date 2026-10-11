//go:build !windows

package main

// isPipeOwnerError is always false: the Unix socket lives in the owner-only
// data directory.
func isPipeOwnerError(error) bool { return false }
