//go:build !windows && !unix

package secmem

import "errors"

// errNoNative tells New to use the heap fallback.
var errNoNative = errors.New("secmem: no off-heap allocator on this platform")

// allocNative is unavailable here; New falls back to a heap slice.
func allocNative(int) (region, bool, error) { return region{}, false, errNoNative }

// freeNative is never reached because no native regions exist here.
func freeNative(region, bool) {}

// HardenProcess has no crash-dump controls on this platform.
func HardenProcess() error { return nil }
