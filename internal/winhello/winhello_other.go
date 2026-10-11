//go:build !windows

package winhello

import "context"

// Available always reports false off Windows.
func Available() (ok bool, reason string) {
	return false, "Windows Hello is only available on Windows"
}

// OpenOrCreate is unavailable off Windows.
func OpenOrCreate(name string) (*Key, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	return nil, ErrUnavailable
}

// Decrypt is unavailable off Windows.
func (k *Key) Decrypt(ctx context.Context, ct []byte, prompt string) ([]byte, error) {
	return nil, ErrUnavailable
}

// DecryptPKCS1v15 is unavailable off Windows.
func (k *Key) DecryptPKCS1v15(ctx context.Context, ct []byte, prompt string) ([]byte, error) {
	return nil, ErrUnavailable
}

// Confirm is unavailable off Windows.
func (k *Key) Confirm(ctx context.Context, prompt string) error { return ErrUnavailable }

// Delete is unavailable off Windows.
func Delete(name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	return ErrUnavailable
}
