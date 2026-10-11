//go:build !windows

package vault

import (
	"errors"
	"fmt"

	"github.com/h-a-forster/keyleash/internal/secmem"
)

// dpapiSupported reports whether DPAPI slots can be created and used.
const dpapiSupported = false

var errNoDPAPI = fmt.Errorf("vault: dpapi slots: %w", errors.ErrUnsupported)

func dpapiProtect([]byte, []byte) ([]byte, error) { return nil, errNoDPAPI }

func dpapiUnprotect([]byte, []byte) (*secmem.Buffer, error) { return nil, errNoDPAPI }
