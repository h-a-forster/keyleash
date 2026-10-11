// Package deps pins the third-party modules the engine is allowed to use so
// parallel work never edits go.mod. Removed once real imports exist.
package deps

import (
	_ "github.com/BurntSushi/toml"
	_ "github.com/Microsoft/go-winio"
	_ "golang.org/x/crypto/argon2"
	_ "golang.org/x/crypto/chacha20poly1305"
	_ "golang.org/x/crypto/hkdf"
)
