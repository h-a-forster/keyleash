//go:build !windows && !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package main

import (
	"errors"
	"os"
)

// isTerminal reports false: hidden input is not implemented here.
func isTerminal(*os.File) bool { return false }

// echoOff is not implemented on this platform; use --stdin.
func echoOff(*os.File) (func(), error) {
	return nil, errors.New("hidden terminal input is not supported on this platform")
}
