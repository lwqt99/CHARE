package bench

import (
	"testing"

	"example.org/chare/internal/auth"
)

func authenticatedStateFixture(t *testing.T) (*workload, *auth.Signer) {
	t.Helper()
	ctx, pp, roots, secrets, signer := deliveryFixture(t)
	w := &workload{ctx: ctx, pp: pp, roots: roots, secrets: secrets,
		rootAuthority: signer.Public(), rootBytes: make([][]byte, len(roots)),
		rootSignatures: make([][]byte, len(roots))}
	for i := range roots {
		w.rootSignatures[i] = signer.Sign(w.rootMessage(i))
		w.rootBytes[i] = auth.Frame("CHARE/certified-root/v1", w.rootMessage(i), w.rootSignatures[i], signer.Public())
	}
	return w, signer
}

func TestAuthorizedRootRechecksCertificateAndPinnedAuthority(t *testing.T) {
	w, signer := authenticatedStateFixture(t)
	if err := w.validateAuthorizedRoot(0); err != nil {
		t.Fatal(err)
	}
	w.rootSignatures[0][0] ^= 1
	if err := w.validateAuthorizedRoot(0); err == nil {
		t.Fatal("corrupted certificate accepted")
	}
	w.rootSignatures[0][0] ^= 1
	w.rootBytes[0][0] ^= 1
	if err := w.validateAuthorizedRoot(0); err == nil {
		t.Fatal("certificate wire substitution accepted")
	}
	w.rootBytes[0][0] ^= 1
	other, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	w.rootSignatures[0] = other.Sign(w.rootMessage(0))
	w.rootBytes[0] = auth.Frame("CHARE/certified-root/v1", w.rootMessage(0), w.rootSignatures[0], other.Public())
	if err := w.validateAuthorizedRoot(0); err == nil {
		t.Fatal("self-selected issuer replaced independently pinned authority")
	}
	w.rootSignatures[0] = signer.Sign(w.rootMessage(1))
	if err := w.validateAuthorizedRoot(0); err == nil {
		t.Fatal("certificate transplanted from another slot")
	}
}

func TestSignedRootStillRequiresFullProjectionChecks(t *testing.T) {
	w, signer := authenticatedStateFixture(t)
	w.roots[0].Proj[0] = w.ctx.Pairing.NewG1().Add(w.roots[0].Proj[0], w.pp.H)
	w.rootSignatures[0] = signer.Sign(w.rootMessage(0))
	w.rootBytes[0] = auth.Frame("CHARE/certified-root/v1", w.rootMessage(0), w.rootSignatures[0], signer.Public())
	if err := w.validateAuthorizedRoot(0); err == nil {
		t.Fatal("a valid signature bypassed algebraic consistency")
	}
}

func TestRefreshAuthenticatesBeforeOpeningPrivateMaterial(t *testing.T) {
	w, signer := receiverRefreshFixture(t)
	snapshot := w.snapshot()
	sig := signer.Sign(snapshot)
	bad := append([]byte(nil), sig...)
	bad[0] ^= 1
	before := w.ctx.Stats()
	if err := w.refreshAuthenticated(0, snapshot, bad); err == nil || w.masks[0][0] != nil {
		t.Fatal("unauthenticated refresh modified receiver state", err)
	}
	if w.ctx.Stats() != before {
		t.Fatal("private group processing preceded snapshot authentication")
	}
	if err := w.refreshAuthenticated(0, append(snapshot, '!'), sig); err == nil {
		t.Fatal("signature accepted on different snapshot bytes")
	}
	if err := w.refreshAuthenticated(0, snapshot, sig); err != nil || w.masks[0][0] == nil {
		t.Fatal("genuine authenticated refresh failed", err)
	}
}
