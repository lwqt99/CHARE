package auth_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"example.org/chare/internal/auth"
)

func TestSignVerifyAndContextSeparation(t *testing.T) {
	signer, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	public := signer.Public()
	message := auth.Frame("CHARE/issuer-record/v1", []byte("root-7"), []byte("generation-2"))
	signature := signer.Sign(message)
	if !auth.Verify(public, message, signature) {
		t.Fatal("valid framed signature rejected")
	}
	if !ed25519.Verify(public, message, signature) {
		t.Fatal("signature is not interoperable with standard Ed25519")
	}
	wrongDomain := auth.Frame("CHARE/snapshot/v1", []byte("root-7"), []byte("generation-2"))
	wrongOrder := auth.Frame("CHARE/issuer-record/v1", []byte("generation-2"), []byte("root-7"))
	changedRecord := auth.Frame("CHARE/issuer-record/v1", []byte("root-7"), []byte("generation-3"))
	for name, altered := range map[string][]byte{
		"domain": wrongDomain, "order": wrongOrder, "record": changedRecord,
	} {
		if auth.Verify(public, altered, signature) {
			t.Fatalf("accepted changed %s", name)
		}
	}
	signature[0] ^= 1
	if auth.Verify(public, message, signature) {
		t.Fatal("accepted modified signature")
	}
}

func TestNewSignerCopiesAndValidatesKey(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	signer, err := auth.NewSigner(private)
	if err != nil {
		t.Fatal(err)
	}
	public := signer.Public()
	private[0] ^= 1 // Caller mutation must not change the signer's owned key.
	if !auth.Verify(public, nil, signer.Sign(nil)) {
		t.Fatal("caller private-key mutation affected signer")
	}
	returnedPublic := signer.Public()
	returnedPublic[0] ^= 1
	if !bytes.Equal(public, signer.Public()) {
		t.Fatal("Public exposed a mutable internal key buffer")
	}
	if _, err := auth.NewSigner(private); !errors.Is(err, auth.ErrInvalidPrivateKey) {
		t.Fatalf("inconsistent seed/public key accepted: %v", err)
	}
	for _, size := range []int{0, ed25519.SeedSize, ed25519.PrivateKeySize - 1, ed25519.PrivateKeySize + 1} {
		if _, err := auth.NewSigner(make([]byte, size)); !errors.Is(err, auth.ErrInvalidPrivateKey) {
			t.Fatalf("private key length %d accepted: %v", size, err)
		}
	}
}

func TestVerifyRejectsMalformedLengths(t *testing.T) {
	signer, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("message")
	signature := signer.Sign(message)
	for _, size := range []int{0, ed25519.PublicKeySize - 1, ed25519.PublicKeySize + 1} {
		if auth.Verify(make([]byte, size), message, signature) {
			t.Fatalf("public key length %d accepted", size)
		}
	}
	for _, size := range []int{0, ed25519.SignatureSize - 1, ed25519.SignatureSize + 1} {
		if auth.Verify(signer.Public(), message, make([]byte, size)) {
			t.Fatalf("signature length %d accepted", size)
		}
	}
}

func TestIndependentKeyDoesNotVerify(t *testing.T) {
	first, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	message := auth.Frame("CHARE/test/v1")
	if auth.Verify(second.Public(), message, first.Sign(message)) {
		t.Fatal("independent key verified signature")
	}
}
