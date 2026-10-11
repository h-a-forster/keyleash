package daemon

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"

	"github.com/h-a-forster/keyleash/internal/vault"
	"github.com/h-a-forster/keyleash/internal/winhello"
)

// Windows Hello key names (scoped per user by winhello).
const (
	// HelloVaultKey is the key wrapping the vault's hello slot.
	HelloVaultKey = "vault"
	// HelloApprovalKey is the key the hello approver signs with.
	HelloApprovalKey = "approval"
)

// helloOps is the subset of *winhello.Key the vault adapter uses.
type helloOps interface {
	KeyName() string
	PublicKey() (*rsa.PublicKey, error)
	Decrypt(ctx context.Context, ct []byte, prompt string) ([]byte, error)
	DecryptPKCS1v15(ctx context.Context, ct []byte, prompt string) ([]byte, error)
}

// helloKey adapts a winhello key to vault.HelloKey and vault.HelloKeyPKCS1.
// It maps winhello.ErrOAEPUnsupported to vault.ErrOAEPUnsupported, which is
// what lets hello slot creation fall back to PKCS#1 v1.5 (spec §5.2).
type helloKey struct{ k helloOps }

var (
	_ vault.HelloKey      = helloKey{}
	_ vault.HelloKeyPKCS1 = helloKey{}
)

func (h helloKey) KeyName() string                    { return h.k.KeyName() }
func (h helloKey) PublicKey() (*rsa.PublicKey, error) { return h.k.PublicKey() }

func (h helloKey) Decrypt(ctx context.Context, ct []byte, prompt string) ([]byte, error) {
	pt, err := h.k.Decrypt(ctx, ct, prompt)
	if err != nil && errors.Is(err, winhello.ErrOAEPUnsupported) {
		return nil, fmt.Errorf("%w: %w", vault.ErrOAEPUnsupported, err)
	}
	return pt, err
}

func (h helloKey) DecryptPKCS1v15(ctx context.Context, ct []byte, prompt string) ([]byte, error) {
	return h.k.DecryptPKCS1v15(ctx, ct, prompt)
}

// openHelloKey opens (creating if needed) the named Hello key as a vault
// HelloKey.
func openHelloKey(name string) (vault.HelloKey, error) {
	k, err := winhello.OpenOrCreate(name)
	if err != nil {
		return nil, err
	}
	return helloKey{k: k}, nil
}

// helloConfirmer is the approval.Confirmer behind the hello approver. The
// key is opened lazily (creating it may itself prompt); any failure is a
// non-confirmation (fail closed).
type helloConfirmer struct {
	available func() (bool, string)
	mu        sync.Mutex
	key       *winhello.Key
}

// Confirm implements approval.Confirmer.
func (c *helloConfirmer) Confirm(ctx context.Context, prompt string) error {
	if ok, reason := c.available(); !ok {
		return fmt.Errorf("%w: %s", winhello.ErrUnavailable, reason)
	}
	c.mu.Lock()
	k := c.key
	if k == nil {
		var err error
		if k, err = winhello.OpenOrCreate(HelloApprovalKey); err != nil {
			c.mu.Unlock()
			return err
		}
		c.key = k
	}
	c.mu.Unlock()
	return k.Confirm(ctx, prompt)
}
