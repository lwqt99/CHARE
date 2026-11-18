package bench

import (
	"bytes"
	"testing"

	"example.org/chare/internal/auth"
	"example.org/chare/internal/core"
)

func senderFixture(t *testing.T) (*workload, *auth.Signer) {
	t.Helper()
	w, authority := authenticatedStateFixture(t)
	w.issuers = []*auth.Signer{authority}
	w.records = [][]*issued{make([]*issued, len(w.roots))}
	w.rows = [][]*core.Row{make([]*core.Row, len(w.roots))}
	for slot := range w.roots {
		r, err := w.issue(0, slot, slot%2 == 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		w.records[0][slot], w.rows[0][slot] = r, r.row
	}
	var err error
	w.prepared, err = core.Aggregate(w.pp, w.roots, w.rows)
	if err != nil {
		t.Fatal(err)
	}
	return w, authority
}

func TestSenderAcquisitionAuthenticatesFullTypedState(t *testing.T) {
	w, authority := senderFixture(t)
	snapshot := w.snapshot()
	sig := authority.Sign(snapshot)
	bad := append([]byte(nil), sig...)
	bad[0] ^= 1
	before := w.ctx.Stats()
	if _, _, _, err := w.acquireSender(snapshot, bad); err == nil {
		t.Fatal("invalid signature accepted")
	}
	if w.ctx.Stats() != before {
		t.Fatal("group processing preceded signature check")
	}
	unrelated := []byte("validly signed but unrelated state")
	if _, _, _, err := w.acquireSender(unrelated, authority.Sign(unrelated)); err == nil {
		t.Fatal("valid signature substituted for actual input binding")
	}
	w.sequence++
	if _, _, _, err := w.acquireSender(snapshot, sig); err == nil {
		t.Fatal("old signed bytes used with different selected current state")
	}
	w.sequence--
	other, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = w.acquireSender(snapshot, other.Sign(snapshot)); err == nil {
		t.Fatal("self-selected signer replaced pinned authority")
	}
}

func TestSenderAcquisitionNeedsNoHolderSecretsAndOwnsItsContext(t *testing.T) {
	w, authority := senderFixture(t)
	snapshot := w.snapshot()
	sig := authority.Sign(snapshot)
	w.secrets, w.masks, w.truth, w.history = nil, nil, nil, nil
	sender, context, wire, err := w.acquireSender(snapshot, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(context, snapshot) || !bytes.Equal(wire, auth.Frame("CHARE/sender-acquisition/v1", snapshot, sig)) {
		t.Fatal("acquisition did not retain actual authenticated bytes")
	}
	snapshot[0] ^= 1
	if bytes.Equal(context, snapshot) {
		t.Fatal("context aliases directory input")
	}
	target, err := sender.Prepare([]core.Literal{{Basis: 0}}, context)
	if err != nil {
		t.Fatal(err)
	}
	if _, key, err := core.Encapsulate(target); err != nil || len(key) != 32 {
		t.Fatal("public-only sender failed", err)
	}
}
