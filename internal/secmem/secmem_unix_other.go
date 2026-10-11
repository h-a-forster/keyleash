//go:build unix && !linux

package secmem

// adviseNoDump is a no-op where MADV_DONTDUMP does not exist.
func adviseNoDump([]byte) {}

// hardenPlatform has nothing beyond RLIMIT_CORE on this platform.
func hardenPlatform() error { return nil }
