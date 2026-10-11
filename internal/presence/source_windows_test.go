//go:build windows

package presence

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestIdleFromTicksWrap(t *testing.T) {
	tests := []struct {
		name   string
		now64  uint64
		last32 uint32
		want   time.Duration
	}{
		{"simple", 10_000, 4_000, 6 * time.Second},
		{"zero", 5, 5, 0},
		{"after 32-bit wrap", 1<<32 + 1_000, 0xFFFFFC18, 2 * time.Second}, // last at 2^32-1000
		{"many wraps later", 5<<32 + 500, 100, 400 * time.Millisecond},
	}
	for _, tc := range tests {
		if got := idleFromTicks(tc.now64, tc.last32); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func wtsBuf(level, state, flags uint32) []byte {
	b := make([]byte, wtsInfoExMinSize)
	binary.LittleEndian.PutUint32(b[0:], level)
	binary.LittleEndian.PutUint32(b[wtsInfoExSessionStateOff:], state)
	binary.LittleEndian.PutUint32(b[wtsInfoExSessionFlagsOff:], flags)
	return b
}

func TestParseWTSInfoEx(t *testing.T) {
	tests := []struct {
		name          string
		b             []byte
		locked, known bool
		err           bool
	}{
		{"locked", wtsBuf(1, wtsActive, wtsSessionStateLock), true, true, false},
		{"unlocked", wtsBuf(1, wtsActive, wtsSessionStateUnlock), false, true, false},
		{"unknown", wtsBuf(1, wtsActive, wtsSessionStateUnknown), false, false, false},
		{"weird flag", wtsBuf(1, wtsActive, 7), false, false, false},
		{"disconnected", wtsBuf(1, wtsDisconnected, wtsSessionStateUnlock), true, true, false},
		{"bad level", wtsBuf(2, wtsActive, wtsSessionStateUnlock), false, false, true},
		{"short", []byte{1, 0, 0, 0}, false, false, true},
	}
	for _, tc := range tests {
		l, k, err := parseWTSInfoEx(tc.b)
		if (err != nil) != tc.err || l != tc.locked || k != tc.known {
			t.Errorf("%s: got %v %v %v", tc.name, l, k, err)
		}
	}
}

func TestWTSAndDesktopLiveAgree(t *testing.T) {
	// The test runs in an unlocked interactive session.
	locked, known, err := wtsLocked()
	if err != nil {
		t.Fatalf("wtsLocked: %v", err)
	}
	dl, derr := desktopLocked()
	t.Logf("wts locked=%v known=%v; desktop locked=%v err=%v", locked, known, dl, derr)
	if known && locked {
		t.Skip("session reports locked; cannot check agreement")
	}
}
