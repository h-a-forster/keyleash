//go:build !windows

package presence

import "time"

// OSSource is the platform presence source.
//
// On non-Windows platforms there is no implementation yet: the stub reports
// zero idle time and an unlocked screen, so idle- and lock-based Away/Locked
// transitions never fire. Sleep detection (Resumed) still works because it
// comes from the Monitor's wall-clock check, and lease expiry still applies.
// Do not rely on presence locking on these platforms. Degraded always
// reports true.
type OSSource struct{}

// Options configures NewOSSourceWithOptions. CountInjected has no effect
// on this platform.
type Options struct {
	CountInjected bool
}

// NewOSSource returns the platform presence source (see OSSource).
func NewOSSource() Source { return &OSSource{} }

// NewOSSourceWithOptions returns an *OSSource; it never fails here.
func NewOSSourceWithOptions(Options) (Source, error) { return &OSSource{}, nil }

// Degraded reports true: presence detection is not implemented here.
func (*OSSource) Degraded() bool { return true }

// DegradedReason explains Degraded.
func (*OSSource) DegradedReason() string {
	return "presence detection not implemented on this platform"
}

// Close is a no-op.
func (*OSSource) Close() error { return nil }

func (*OSSource) IdleFor() (time.Duration, error) { return 0, nil }

func (*OSSource) ScreenLocked() (bool, error) { return false, nil }
