//go:build unix

package main

import (
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// forwardedSignals are the signals `run` intercepts and passes on.
var forwardedSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

// handleRunSignal forwards sig to the child. SIGINT and SIGQUIT typed at the
// terminal already reach the child (it is in keyleash's foreground process
// group), so they are forwarded only when keyleash is not in the terminal's
// foreground group (i.e. the signal was sent to keyleash alone). SIGTERM and
// SIGHUP also revoke the pass immediately.
func handleRunSignal(cmd *exec.Cmd, sig os.Signal, onTerminate func()) {
	if cmd.Process == nil {
		return
	}
	switch sig {
	case os.Interrupt, syscall.SIGQUIT:
		if inForegroundGroup() {
			return
		}
		_ = cmd.Process.Signal(sig)
	default:
		_ = cmd.Process.Signal(sig)
		onTerminate()
	}
}

// inForegroundGroup reports whether this process belongs to the
// foreground process group of the terminal on stdin.
func inForegroundGroup() bool {
	pgrp, err := unix.IoctlGetInt(int(os.Stdin.Fd()), unix.TIOCGPGRP)
	if err != nil {
		return false
	}
	return pgrp == unix.Getpgrp()
}

// signalExitCode maps death by signal to the shell convention 128+n.
func signalExitCode(ps *os.ProcessState) (int, bool) {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), true
	}
	return 0, false
}
