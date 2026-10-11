// Package secmem provides wipeable buffers for key material.
//
// Where the platform allows, a Buffer lives in pages allocated outside the Go
// heap (VirtualAlloc + VirtualLock on Windows, mmap + mlock on Unix), so the
// garbage collector never copies it and the OS is asked not to page it out.
// Locking is best effort: if the OS refuses (for example because of a low
// RLIMIT_MEMLOCK), the buffer still works and Locked reports false. On
// platforms without either mechanism the buffer falls back to a heap slice.
//
// This is memory hygiene, not a security boundary: code running as the same
// user can read process memory. See docs/SPEC.md §5.5.
package secmem

import (
	"errors"
	"runtime"
	"sync"
)

// MaxSize is the largest buffer New will allocate. Key material is small;
// the limit keeps a bad length from exhausting locked memory.
const MaxSize = 1 << 20

// ErrInvalidSize is returned by New for a non-positive or too large size.
var ErrInvalidSize = errors.New("secmem: invalid buffer size")

// Buffer is a fixed-size region of memory for secrets. The zero value is not
// usable; create buffers with New. A Buffer is safe for concurrent calls to
// Destroy, but callers must not use the slice from Bytes after Destroy.
type Buffer struct {
	mu        sync.Mutex
	data      []byte // len == cap == requested size; nil after Destroy
	region    region // platform allocation backing data
	locked    bool
	destroyed bool
}

// region is the platform-specific allocation backing a Buffer.
type region struct {
	mem    []byte // whole allocation (page rounded), nil for heap fallback
	native bool   // true when mem came from the OS allocator, not the Go heap
}

// New returns a zeroed Buffer of n bytes. It prefers locked, off-heap memory
// and falls back to the Go heap when the platform allocator is unavailable.
func New(n int) (*Buffer, error) {
	if n <= 0 || n > MaxSize {
		return nil, ErrInvalidSize
	}
	r, locked, err := allocNative(n)
	if err != nil {
		// Off-heap allocation failed; degrade to the heap rather than
		// failing the caller. The buffer is still wiped on Destroy.
		r = region{mem: make([]byte, n)}
		locked = false
	}
	b := &Buffer{
		data:   r.mem[:n:n],
		region: r,
		locked: locked,
	}
	return b, nil
}

// Bytes returns the buffer's memory. The slice has len and cap equal to the
// size passed to New. It returns nil after Destroy. The caller must not
// retain the slice beyond the Buffer's lifetime.
func (b *Buffer) Bytes() []byte {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data
}

// Len returns the usable size of the buffer, or 0 after Destroy.
func (b *Buffer) Len() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.data)
}

// Locked reports whether the OS agreed to keep the buffer's pages resident.
func (b *Buffer) Locked() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.locked
}

// Native reports whether the buffer lives outside the Go heap.
func (b *Buffer) Native() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.region.native
}

// Destroy wipes the buffer and releases its memory. It is idempotent and
// safe to call on a nil Buffer.
func (b *Buffer) Destroy() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.destroyed {
		return
	}
	b.destroyed = true
	Wipe(b.region.mem)
	if b.region.native {
		freeNative(b.region, b.locked)
	}
	b.data = nil
	b.region = region{}
	b.locked = false
}

// Wipe overwrites b with zeros. It is a no-op for an empty slice.
func Wipe(b []byte) {
	if len(b) == 0 {
		return
	}
	clear(b)
	// Keep the slice reachable until after the clear so the compiler cannot
	// treat the stores as dead.
	runtime.KeepAlive(b)
}

// roundUp rounds n up to a multiple of page (a power of two).
func roundUp(n, page int) int {
	return (n + page - 1) &^ (page - 1)
}
