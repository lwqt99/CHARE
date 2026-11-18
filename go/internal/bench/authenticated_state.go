package bench

import (
	"bytes"
	"errors"

	"example.org/chare/internal/auth"
	"example.org/chare/internal/core"
)

func (w *workload) rootMessage(slot int) []byte {
	return auth.Frame("CHARE/authorized-root/v1", []byte(ProtocolVersion), w.pp.Bytes(), number(uint64(slot)), w.roots[slot].Bytes())
}

// The authority is pinned independently of the submitted certificate. This
// validates generated typed objects; it is not a hostile wire-format decoder.
func (w *workload) validateAuthorizedRoot(slot int) error {
	if slot < 0 || slot >= len(w.roots) || slot >= len(w.rootSignatures) || slot >= len(w.rootBytes) || w.roots[slot] == nil {
		return errors.New("missing authorized root")
	}
	msg := w.rootMessage(slot)
	if !auth.Verify(w.rootAuthority, msg, w.rootSignatures[slot]) {
		return errors.New("root certificate authentication failed")
	}
	expected := auth.Frame("CHARE/certified-root/v1", msg, w.rootSignatures[slot], w.rootAuthority)
	if !bytes.Equal(expected, w.rootBytes[slot]) {
		return errors.New("certificate wire differs from bound root")
	}
	return core.ValidateRoot(w.pp, w.roots[slot])
}

func (w *workload) validateSnapshot(snapshot, signature []byte) error {
	if !auth.Verify(w.rootAuthority, snapshot, signature) {
		return errors.New("snapshot authentication failed")
	}
	return nil
}

// Acquisition uses generated typed public objects and a separately pinned
// authority. Canonical reserialization binds those objects to the exact signed
// bytes. The trusted current-snapshot interface still selects the current
// sequence; signature validity alone is not a freshness or fork proof.
func (w *workload) acquireSender(snapshot, signature []byte) (*core.SenderState, []byte, []byte, error) {
	if err := w.validateSnapshot(snapshot, signature); err != nil {
		return nil, nil, nil, err
	}
	if w.prepared == nil || !bytes.Equal(snapshot, w.snapshot()) {
		return nil, nil, nil, errors.New("signed snapshot differs from typed public sender inputs")
	}
	sender, err := w.prepared.CopySender()
	if err != nil {
		return nil, nil, nil, err
	}
	if !bytes.Equal(sender.Bytes(), w.prepared.SenderBytes()) {
		return nil, nil, nil, errors.New("sender copy differs from authenticated material")
	}
	context := append([]byte(nil), snapshot...)
	wire := auth.Frame("CHARE/sender-acquisition/v1", context, signature)
	return sender, context, wire, nil
}

// Bind the authenticated snapshot to the exact typed state used below BEFORE
// opening private deliveries. Freshness still comes from the existing trusted
// current-snapshot interface; equality here is not rollback/fork detection.
func (w *workload) refreshAuthenticated(slot int, snapshot, signature []byte) error {
	if err := w.validateSnapshot(snapshot, signature); err != nil {
		return err
	}
	if w.prepared == nil || !bytes.Equal(snapshot, w.snapshot()) {
		return errors.New("signed snapshot differs from typed receiver refresh inputs")
	}
	return w.refresh(slot)
}
