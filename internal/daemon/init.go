package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/h-a-forster/keyleash/internal/config"
	"github.com/h-a-forster/keyleash/internal/vault"
)

// InitOptions configures Init.
type InitOptions struct {
	// Method is the first slot: "hello" (Windows Hello) or "passphrase".
	Method string
	// Passphrase is required for "passphrase". It is not retained; the
	// caller wipes it.
	Passphrase []byte
	// Profile is the config profile ("recommended", "strict", "relaxed";
	// default "recommended").
	Profile string
	// Context cancels a Windows Hello prompt (nil: background).
	Context context.Context
}

// ErrAlreadyInitialized is returned by Init when a vault already exists.
var ErrAlreadyInitialized = errors.New("keyleash: a vault already exists in this data directory")

// Init creates a new data directory offline: an owner-only directory, the
// vault with the first slot plus a recovery slot (and the daemon's integrity
// root), and a commented config.toml for the profile (an existing
// config.toml is kept). It returns the recovery code, which must be shown to
// the user once and never stored.
func Init(dataDir string, opts InitOptions) (recoveryCode string, err error) {
	if dataDir == "" {
		if dataDir, err = DefaultDataDir(); err != nil {
			return "", err
		}
	}
	profile := opts.Profile
	if profile == "" {
		profile = "recommended"
	}
	cfg, err := config.Default(profile)
	if err != nil {
		return "", err
	}
	if err := vault.SecureDir(dataDir); err != nil {
		return "", fmt.Errorf("keyleash: secure data dir: %w", err)
	}
	spec := vault.SlotSpec{Label: "first", Context: opts.Context}
	switch opts.Method {
	case "passphrase":
		if len(opts.Passphrase) < vault.MinPassphraseLen {
			return "", fmt.Errorf("keyleash: passphrase must be at least %d bytes", vault.MinPassphraseLen)
		}
		spec.Type, spec.Passphrase = vault.SlotPassphrase, opts.Passphrase
	case "hello":
		hk, herr := openHelloKey(HelloVaultKey)
		if herr != nil {
			return "", fmt.Errorf("keyleash: Windows Hello: %w", herr)
		}
		spec.Type, spec.Hello, spec.HelloPrompt = vault.SlotHello, hk, "Create the keyleash vault"
	default:
		return "", errors.New(`keyleash: init method must be "hello" or "passphrase"`)
	}
	v, code, err := vault.Create(filepath.Join(dataDir, VaultFile), spec)
	if err != nil {
		if errors.Is(err, vault.ErrExists) {
			return "", ErrAlreadyInitialized
		}
		return "", fmt.Errorf("keyleash: create vault: %w", err)
	}
	defer v.Lock()
	if _, err := ensureRootEntry(v); err != nil {
		return "", fmt.Errorf("keyleash: create integrity key: %w", err)
	}
	cpath := filepath.Join(dataDir, ConfigFile)
	if _, serr := os.Stat(cpath); errors.Is(serr, os.ErrNotExist) {
		text, terr := configTemplate(cfg)
		if terr != nil {
			return "", terr
		}
		if err := writeFileAtomic(cpath, []byte(text)); err != nil {
			return "", fmt.Errorf("keyleash: write config: %w", err)
		}
	}
	return code, nil
}

// configTemplate renders a config.toml that selects the profile and lists
// every effective default as a comment, so editing a value means removing
// the leading "# ".
func configTemplate(cfg *config.Config) (string, error) {
	enc, err := cfg.Encode()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# keyleash configuration (docs/SPEC.md §14).\n")
	b.WriteString("# Every option has a default from the profile below. Uncomment a line to\n")
	b.WriteString("# override it; unknown keys are rejected so typos cannot weaken protection.\n")
	b.WriteString("# Check with `keyleash config check`.\n\n")
	b.WriteString("profile = " + strconv.Quote(cfg.Profile) + "\n\n")
	b.WriteString("# Effective defaults for this profile:\n")
	for _, line := range strings.Split(strings.TrimRight(enc, "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "profile =") {
			continue
		}
		if line == "" {
			b.WriteString("\n")
			continue
		}
		b.WriteString("# " + line + "\n")
	}
	return b.String(), nil
}
