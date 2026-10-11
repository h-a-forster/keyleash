//go:build windows

package main

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// detachedProcAttr starts a background process without a console and in
// its own process group, so closing this terminal or pressing Ctrl-C here
// does not stop it.
func detachedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
		HideWindow:    true,
	}
}
