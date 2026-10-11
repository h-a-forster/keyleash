//go:build unix

package main

import "syscall"

// detachedProcAttr starts a background process in a new session, detached
// from this terminal.
func detachedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
