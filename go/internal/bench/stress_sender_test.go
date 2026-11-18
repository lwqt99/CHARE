package bench

import (
	"bytes"
	"math/big"
	"testing"

	"example.org/chare/internal/core"
)

func TestCohortSenderRejectsParentEventAndStateSubstitution(t *testing.T) {
	w, publisher := senderFixture(t)
	parent := w.snapshot()
	parentSig := publisher.Sign(parent)
	prepared, err := core.Aggregate(w.pp, w.roots[1:2], [][]*core.Row{{w.rows[0][1]}})
	if err != nil {
		t.Fatal(err)
	}
	event, err := w.cohortEvent(prepared.Slots)
	if err != nil {
		t.Fatal(err)
	}
	eventSig := publisher.Sign(event)
	snapshot := cohortSnapshot(prepared, parent, parentSig, event, eventSig)
	sig := publisher.Sign(snapshot)
	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 1
	before := w.ctx.Stats()
	if _, _, _, err = w.acquireCohortSender(prepared, parent, parentSig, event, eventSig, snapshot, badSig); err == nil {
		t.Fatal("invalid signature accepted")
	}
	if w.ctx.Stats() != before {
		t.Fatal("point work before authentication")
	}
	wrongEvent, err := w.cohortEvent([]int{0})
	if err != nil {
		t.Fatal(err)
	}
	wrongEventSig := publisher.Sign(wrongEvent)
	wrongSnapshot := cohortSnapshot(prepared, parent, parentSig, wrongEvent, wrongEventSig)
	if _, _, _, err = w.acquireCohortSender(prepared, parent, parentSig, wrongEvent, wrongEventSig, wrongSnapshot, publisher.Sign(wrongSnapshot)); err == nil {
		t.Fatal("signed event names a different cohort")
	}
	if _, _, _, err = w.acquireSender(snapshot, sig); err == nil {
		t.Fatal("branch installed as main snapshot")
	}
	if _, _, _, err = w.acquireCohortSender(w.prepared, parent, parentSig, event, eventSig, snapshot, sig); err == nil {
		t.Fatal("full-cohort state transplanted into subset")
	}
	w.sequence++
	if _, _, _, err = w.acquireCohortSender(prepared, parent, parentSig, event, eventSig, snapshot, sig); err == nil {
		t.Fatal("old parent accepted as selected current state")
	}
}

func TestCohortSenderUsesOnlyPublicInputsAndIndependentCopy(t *testing.T) {
	w, publisher := senderFixture(t)
	parent := w.snapshot()
	parentSig := publisher.Sign(parent)
	prepared, err := core.Aggregate(w.pp, w.roots[1:2], [][]*core.Row{{w.rows[0][1]}})
	if err != nil {
		t.Fatal(err)
	}
	event, err := w.cohortEvent(prepared.Slots)
	if err != nil {
		t.Fatal(err)
	}
	eventSig := publisher.Sign(event)
	snapshot := cohortSnapshot(prepared, parent, parentSig, event, eventSig)
	sig := publisher.Sign(snapshot)
	secret := w.secrets[1]
	r := w.records[0][1]
	mask, err := OpenScalar(w.ctx, w.pp.G, secret.Z, r.delivery, r.metadata, publisher.Public())
	if err != nil {
		t.Fatal(err)
	}
	help, err := core.Help(prepared, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = core.VerifyHelp(prepared, help); err != nil {
		t.Fatal(err)
	}
	w.secrets, w.masks, w.truth, w.history = nil, nil, nil, nil
	sender, context, wire, err := w.acquireCohortSender(prepared, parent, parentSig, event, eventSig, snapshot, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(context, snapshot) || len(wire) <= len(snapshot) {
		t.Fatal("missing actual authenticated envelope")
	}
	snapshot[0] ^= 1
	prepared.Slots[0] = 0
	target, err := sender.Prepare([]core.Literal{{Basis: 0}}, context)
	if err != nil {
		t.Fatal("copy aliases original cohort", err)
	}
	ct, key, err := core.Encapsulate(target)
	if err != nil || len(key) != 32 {
		t.Fatal("public branch sender failed", err)
	}
	got, err := core.Decapsulate(target, ct, secret, []*big.Int{mask}, help)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("qualified subset receiver failed", err)
	}
}
