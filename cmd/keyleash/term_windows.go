//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// isTerminal reports whether f is a console.
func isTerminal(f *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}

// echoOff clears ENABLE_ECHO_INPUT on the console behind f (keeping line
// editing and Ctrl-C processing) and returns a function restoring the
// original mode.
func echoOff(f *os.File) (restore func(), err error) {
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return nil, err
	}
	hidden := (mode &^ windows.ENABLE_ECHO_INPUT) | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT
	if err := windows.SetConsoleMode(h, hidden); err != nil {
		return nil, err
	}
	return func() { _ = windows.SetConsoleMode(h, mode) }, nil
}
