//go:build !windows && !unix

package main

import "syscall"

// detachedProcAttr has no detaching attributes on this platform.
func detachedProcAttr() *syscall.SysProcAttr { return nil }
