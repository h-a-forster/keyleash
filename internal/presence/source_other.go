//go:build !windows

package presence

import "time"

type osSource struct{}

// NewOSSource returns the platform presence source.
//
// On non-Windows platforms there is no implementation yet: the stub reports
// zero idle time and an unlocked screen, so idle- and lock-based Away/Locked
// transitions never fire. Sleep detection (Resumed) still works because it
// comes from the Monitor's wall-clock check, and lease expiry still applies.
// Do not rely on presence locking on these platforms.
func NewOSSource() Source { return osSource{} }

func (osSource) IdleFor() (time.Duration, error) { return 0, nil }

func (osSource) ScreenLocked() (bool, error) { return false, nil }
