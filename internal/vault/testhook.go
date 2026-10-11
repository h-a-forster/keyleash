package vault

import (
	"sync"
	"testing"
)

var testKDFMu sync.Mutex

// SetTestKDFParams lowers the Argon2id cost used for NEW passphrase and
// recovery slots to a trivial level (t=1, 64 KiB, 1 thread, no tuning) so
// that tests in other packages (e.g. the daemon's end-to-end tests) can
// create and unlock vaults quickly. Existing slots keep their stored
// parameters.
//
// It exists for tests only: it panics unless the running binary is a test
// binary (testing.Testing), so production code can never weaken the KDF
// through it. It returns a function that restores the previous parameters.
// It is not safe to call concurrently with slot creation.
func SetTestKDFParams() (restore func()) {
	if !testing.Testing() {
		panic("vault: SetTestKDFParams called outside a test binary")
	}
	testKDFMu.Lock()
	defer testKDFMu.Unlock()
	prevDefaults, prevTarget := kdfDefaults, kdfTarget
	kdfDefaults = kdfParams{Time: 1, MemoryKiB: 64, Threads: 1}
	kdfTarget = 0
	return func() {
		testKDFMu.Lock()
		defer testKDFMu.Unlock()
		kdfDefaults, kdfTarget = prevDefaults, prevTarget
	}
}
