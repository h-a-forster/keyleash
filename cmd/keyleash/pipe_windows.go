//go:build windows

package main

import (
	"errors"

	"github.com/h-a-forster/keyleash/internal/client"
)

// isPipeOwnerError reports whether err is the client's refusal to use an
// admin pipe owned by another account.
func isPipeOwnerError(err error) bool { return errors.Is(err, client.ErrPipeOwner) }
