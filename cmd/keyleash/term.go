package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// readHidden prompts on out and reads one line from the terminal f with
// echo switched off. The terminal mode is restored on every path: normal
// return, read error, and Ctrl-C / termination (which ends the process with
// exit code 130 after restoring). The caller wipes the result.
func readHidden(f *os.File, out io.Writer, prompt string) ([]byte, error) {
	restore, err := echoOff(f)
	if err != nil {
		return nil, fmt.Errorf("cannot hide terminal input (%v); pipe the secret in with --stdin", err)
	}
	var once sync.Once
	restoreOnce := func() { once.Do(restore) }
	defer restoreOnce()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-sig:
			restoreOnce()
			fmt.Fprintln(out)
			fmt.Fprintln(out, "keyleash: interrupted")
			os.Exit(exitInterrupted)
		case <-done:
		}
	}()

	fmt.Fprint(out, prompt)
	line, err := readLineBounded(f)
	fmt.Fprintln(out)
	return line, err
}
