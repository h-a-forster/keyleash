//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// forwardedSignals are the signals `run` intercepts. On Windows, Ctrl-C and
// Ctrl-Break arrive as os.Interrupt and console close, logoff and shutdown
// as SIGTERM.
var forwardedSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

// handleRunSignal reacts to a signal while the child runs. The console
// delivers Ctrl-C to every process attached to it, so the child already has
// it and keyleash just keeps waiting. On close/logoff/shutdown Windows ends
// all console processes within seconds: revoke the pass right away.
func handleRunSignal(_ *exec.Cmd, sig os.Signal, onTerminate func()) {
	if sig == syscall.SIGTERM {
		onTerminate()
	}
}

// signalExitCode: Windows processes have no terminating signal.
func signalExitCode(*os.ProcessState) (int, bool) { return 0, false }
