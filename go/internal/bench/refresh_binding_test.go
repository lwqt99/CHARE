package bench

import (
	"math/big"
	"testing"

	"example.org/chare/internal/auth"
	"example.org/chare/internal/core"
)

func receiverRefreshFixture(t *testing.T) (*workload, *auth.Signer) {
	t.Helper()
	w, signer := senderFixture(t)
	w.masks = [][]*big.Int{make([]*big.Int, len(w.roots))}
	return w, signer
}

func TestRefreshRejectsAuthenticUnrelatedSnapshot(t *testing.T) {
	w, signer := receiverRefreshFixture(t)
	snapshot := []byte("valid signature, but no selected records or parameter binding")
	before := w.ctx.Stats()
	if err := w.refreshAuthenticated(0, snapshot, signer.Sign(snapshot)); err == nil {
		t.Fatal("authentic unrelated bytes authorized private refresh")
	}
	if w.masks[0][0] != nil || w.ctx.Stats() != before {
		t.Fatal("mismatched snapshot reached private opening or changed local state")
	}
}

func TestRefreshRejectsAuthenticOldSnapshotAfterNewVersion(t *testing.T) {
	w, signer := receiverRefreshFixture(t)
	old := w.snapshot()
	oldSig := signer.Sign(old)
	replacement, err := w.issue(0, 0, true, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.validateRecord(0, 0, replacement); err != nil {
		t.Fatal(err)
	}
	if err = w.install(0, 0, replacement); err != nil {
		t.Fatal(err)
	}
	before := w.ctx.Stats()
	if err = w.refreshAuthenticated(0, old, oldSig); err == nil {
		t.Fatal("old authentic snapshot was applied to a different selected version")
	}
	if w.masks[0][0] != nil || w.ctx.Stats() != before {
		t.Fatal("rejected old snapshot reached private opening")
	}
	current := w.snapshot()
	if err = w.refreshAuthenticated(0, current, signer.Sign(current)); err != nil {
		t.Fatal("correctly bound current snapshot failed", err)
	}
	delta, err := OpenScalar(w.ctx, w.pp.G, w.secrets[0].Z, replacement.delivery, replacement.metadata, signer.Public())
	if err != nil || w.masks[0][0] == nil || w.masks[0][0].Cmp(delta) != 0 {
		t.Fatal("refresh did not install the actual selected delivery", err)
	}
}

func TestRefreshKeepsAllOldMasksWhenLaterNamespaceFails(t *testing.T) {
	w, signer := receiverRefreshFixture(t)
	w.issuers = append(w.issuers, signer)
	w.records = append(w.records, make([]*issued, len(w.roots)))
	w.rows = append(w.rows, make([]*core.Row, len(w.roots)))
	w.masks = append(w.masks, make([]*big.Int, len(w.roots)))
	for slot := range w.roots {
		r, err := w.issue(1, slot, false, 1)
		if err != nil {
			t.Fatal(err)
		}
		w.records[1][slot], w.rows[1][slot] = r, r.row
	}
	var err error
	w.prepared, err = core.Aggregate(w.pp, w.roots, w.rows)
	if err != nil {
		t.Fatal(err)
	}
	// Two historical canonical values must remain intact after a later failure.
	oldA, oldB := big.NewInt(0), big.NewInt(1)
	w.masks[0][0], w.masks[1][0] = oldA, oldB
	bad := w.records[1][0].delivery
	shared := w.ctx.SourceScale(bad.U, w.secrets[0].Z)
	pad := scalarDeliveryMask(bad.Precontext, shared.Bytes(), len(bad.Payload))
	invalid := w.ctx.P.FillBytes(make([]byte, len(bad.Payload)))
	for i := range bad.Payload {
		bad.Payload[i] = invalid[i] ^ pad[i]
	}
	bad.Signature = signer.Sign(scalarSignatureMessage(bad))
	snapshot := w.snapshot()
	if err = w.refreshAuthenticated(0, snapshot, signer.Sign(snapshot)); err == nil {
		t.Fatal("signed noncanonical second delivery was accepted")
	}
	if w.masks[0][0] != oldA || w.masks[1][0] != oldB || oldA.Sign() != 0 || oldB.Cmp(big.NewInt(1)) != 0 {
		t.Fatal("failed refresh partially replaced retained receiver state")
	}
	// Correcting the actual row produces a complete, successful new transaction.
	replacement, err := w.issue(1, 0, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.install(1, 0, replacement); err != nil {
		t.Fatal(err)
	}
	snapshot = w.snapshot()
	if err = w.refreshAuthenticated(0, snapshot, signer.Sign(snapshot)); err != nil {
		t.Fatal("corrected complete refresh failed", err)
	}
	if w.masks[0][0] == oldA || w.masks[1][0] == oldB {
		t.Fatal("successful refresh did not commit both selected openings")
	}
	if oldA.Sign() != 0 || oldB.Cmp(big.NewInt(1)) != 0 {
		t.Fatal("successful refresh overwrote separately retained old state")
	}
}
