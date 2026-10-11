//go:build !windows && !unix

package main

import (
	"os"
	"os/exec"
)

// forwardedSignals are the signals `run` intercepts.
var forwardedSignals = []os.Signal{os.Interrupt}

// handleRunSignal forwards sig to the child.
func handleRunSignal(cmd *exec.Cmd, sig os.Signal, _ func()) {
	if cmd.Process != nil {
		_ = cmd.Process.Signal(sig)
	}
}

// signalExitCode is not available on this platform.
func signalExitCode(*os.ProcessState) (int, bool) { return 0, false }
