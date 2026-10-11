package secmem

import (
	"bytes"
	"errors"
	"runtime"
	"sync"
	"testing"
)

func TestNewSizes(t *testing.T) {
	tests := []struct {
		name    string
		n       int
		wantErr bool
	}{
		{"one", 1, false},
		{"key", 32, false},
		{"page", 4096, false},
		{"over page", 4097, false},
		{"max", MaxSize, false},
		{"zero", 0, true},
		{"negative", -1, true},
		{"too large", MaxSize + 1, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := New(tc.n)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidSize) {
					t.Fatalf("New(%d) err = %v, want ErrInvalidSize", tc.n, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%d): %v", tc.n, err)
			}
			defer b.Destroy()
			p := b.Bytes()
			if len(p) != tc.n || cap(p) != tc.n {
				t.Fatalf("len/cap = %d/%d, want %d", len(p), cap(p), tc.n)
			}
			if !bytes.Equal(p, make([]byte, tc.n)) {
				t.Fatal("new buffer not zeroed")
			}
			for i := range p {
				p[i] = 0xA5
			}
			if b.Len() != tc.n {
				t.Fatalf("Len = %d", b.Len())
			}
		})
	}
}

func TestNativeOnSupportedPlatforms(t *testing.T) {
	b, err := New(32)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Destroy()
	switch runtime.GOOS {
	case "windows", "linux", "darwin", "freebsd", "openbsd", "netbsd":
		if !b.Native() {
			t.Fatal("expected off-heap allocation")
		}
	}
	t.Logf("native=%v locked=%v", b.Native(), b.Locked())
}

func TestDestroyIdempotentAndNil(t *testing.T) {
	b, err := New(16)
	if err != nil {
		t.Fatal(err)
	}
	copy(b.Bytes(), "secretsecretsecr")
	b.Destroy()
	b.Destroy()
	if b.Bytes() != nil || b.Len() != 0 || b.Locked() || b.Native() {
		t.Fatal("destroyed buffer still exposes memory")
	}
	var nb *Buffer
	nb.Destroy()
	if nb.Bytes() != nil || nb.Len() != 0 {
		t.Fatal("nil buffer misbehaves")
	}
}

func TestDestroyWipesHeapFallback(t *testing.T) {
	// A heap-backed buffer stays readable after Destroy, so the wipe can be
	// observed directly. Native pages are unmapped and cannot be read back.
	mem := make([]byte, 64)
	b := &Buffer{data: mem[:64:64], region: region{mem: mem}}
	copy(b.Bytes(), bytes.Repeat([]byte{0xFF}, 64))
	b.Destroy()
	if !bytes.Equal(mem, make([]byte, 64)) {
		t.Fatal("heap fallback not wiped on Destroy")
	}
}

func TestWipe(t *testing.T) {
	tests := [][]byte{nil, {}, {1}, bytes.Repeat([]byte{0x7F}, 1000)}
	for _, in := range tests {
		Wipe(in)
		for _, c := range in {
			if c != 0 {
				t.Fatal("not wiped")
			}
		}
	}
}

func TestConcurrentDestroy(t *testing.T) {
	for i := 0; i < 200; i++ {
		b, err := New(32)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for j := 0; j < 8; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = b.Len()
				b.Destroy()
			}()
		}
		wg.Wait()
		if b.Bytes() != nil {
			t.Fatal("buffer alive after concurrent destroy")
		}
	}
}

func TestHardenProcess(t *testing.T) {
	if err := HardenProcess(); err != nil {
		t.Fatalf("HardenProcess: %v", err)
	}
}
