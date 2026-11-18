// Package auth provides independent bitstring authentication using the Go
// standard library's Ed25519 implementation. It does not establish currentness,
// absence of forks, real-world qualifications, or honest source generation.
//
// Callers should sign Frame(domain, fields...) with a protocol-specific domain
// and the complete immutable context. Sign and Verify authenticate exactly the
// supplied bytes; they do not add an implicit domain or interpret record fields.
package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

// ErrInvalidPrivateKey reports a wrong-length key or a key whose public half
// does not match the public key derived from its seed.
var ErrInvalidPrivateKey = errors.New("auth: invalid Ed25519 private key")

// Signer owns a copy of an Ed25519 private key. Construct it with Generate or
// NewSigner. Its zero value is not initialized. Concurrent signing is supported;
// neither Public nor Sign exposes the retained private-key buffer.
type Signer struct {
	private ed25519.PrivateKey
}

// Generate creates an independent signing key using crypto/rand.Reader.
func Generate() (*Signer, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signer{private: private}, nil
}

// NewSigner validates and copies a standard-library Ed25519 private key.
// It accepts the 64-byte seed-and-public-key representation, not a raw seed.
func NewSigner(private ed25519.PrivateKey) (*Signer, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	derived := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
	if !bytes.Equal(private[ed25519.SeedSize:], derived[ed25519.SeedSize:]) {
		return nil, ErrInvalidPrivateKey
	}
	return &Signer{private: derived}, nil
}

// Public returns a fresh copy of the signing key's public key.
// It panics if the receiver is nil or uninitialized.
func (s *Signer) Public() ed25519.PublicKey {
	s.requireInitialized()
	return append(ed25519.PublicKey(nil), s.private[ed25519.SeedSize:]...)
}

// Sign returns a standard Ed25519 signature of the exact message bytes.
// It panics if the receiver is nil or uninitialized.
func (s *Signer) Sign(message []byte) []byte {
	s.requireInitialized()
	return ed25519.Sign(s.private, message)
}

// Verify checks a standard Ed25519 signature of the exact message bytes.
// Malformed public-key or signature lengths return false rather than panic.
func Verify(public ed25519.PublicKey, message, signature []byte) bool {
	if len(public) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(public, message, signature)
}

func (s *Signer) requireInitialized() {
	if s == nil || len(s.private) != ed25519.PrivateKeySize {
		panic("auth: uninitialized signer")
	}
}
