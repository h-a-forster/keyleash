//go:build !windows

package runjob

// Supported reports whether job objects are available (never here: Unix
// process groups and sessions can be left by any process, so they cannot
// confine an agent).
func Supported() bool { return false }

// Manager is not available on this platform; New returns nil and every
// method of a nil *Manager reports ErrUnsupported or does nothing.
type Manager struct{}

// New returns nil on this platform.
func New(bool) *Manager { return nil }

// Confine is not supported here.
func (*Manager) Confine(string, int, int64) error { return ErrUnsupported }

// Member is not supported here.
func (*Manager) Member(string, int) (bool, error) { return false, ErrUnsupported }

// MemberOfAny is not supported here.
func (*Manager) MemberOfAny(int) (bool, error) { return false, ErrUnsupported }

// Sweep does nothing here.
func (*Manager) Sweep(func(string) bool) {}

// Len is always 0 here.
func (*Manager) Len() int { return 0 }

// Close does nothing here.
func (*Manager) Close() {}
