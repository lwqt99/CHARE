package bench

import (
	"bytes"
	"testing"

	"github.com/Nik-U/pbc"
	"example.org/chare/internal/core"
)

func TestColdAuditRebuildsWithoutPrivateState(t *testing.T) {
	w, authority := senderFixture(t)
	for a := range w.records {
		w.history = append(w.history, w.records[a]...)
	}
	r, err := w.issue(0, 1, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.install(0, 1, r); err != nil {
		t.Fatal(err)
	}
	snapshot := w.snapshot()
	h, err := core.Help(w.prepared, 0)
	if err != nil {
		t.Fatal(err)
	}
	in := w.coldInput(snapshot, authority.Sign(snapshot), h)
	w.secrets, w.masks, w.truth, w.prepared, w.records, w.rows, w.issuers = nil, nil, nil, nil, nil, nil, nil
	wire, err := verifyColdPublic(in, 0)
	if err != nil || len(wire) <= len(snapshot) {
		t.Fatal("independent replay needs actual complete public payload", err)
	}
	snapshot[0] ^= 1
	if bytes.Contains(wire, snapshot) {
		t.Fatal("delivered bytes alias snapshot input")
	}
}

func TestColdAuditRejectsSignedWrongAggregateAndMissingHistory(t *testing.T) {
	w, authority := senderFixture(t)
	for a := range w.records {
		w.history = append(w.history, w.records[a]...)
	}
	r, err := w.issue(0, 1, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.install(0, 1, r); err != nil {
		t.Fatal(err)
	}
	h, err := core.Help(w.prepared, 0)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := w.snapshot()
	in := w.coldInput(snapshot, authority.Sign(snapshot), h)
	if _, err = verifyColdPublic(in, 0); err != nil {
		t.Fatal(err)
	}
	oldHistory := in.history
	in.history = in.history[:len(in.history)-1]
	if _, err = verifyColdPublic(in, 0); err == nil {
		t.Fatal("missing generation accepted")
	}
	in.history = append([]*issued(nil), oldHistory...)
	in.history[0], in.history[1] = in.history[1], in.history[0]
	if _, err = verifyColdPublic(in, 0); err == nil {
		t.Fatal("initial history reordered")
	}
	in.history = oldHistory
	in.help = nil
	if _, err = verifyColdPublic(in, 0); err == nil {
		t.Fatal("missing help accepted")
	}
	// A correct signature on inconsistent cache/context must not be enough.
	badRow, _, err := core.Issue(w.pp, w.roots[1], true)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.prepared.UpdateRow(0, 1, badRow); err != nil {
		t.Fatal(err)
	}
	badSnapshot := w.snapshot()
	badHelp, err := core.Help(w.prepared, 0)
	if err != nil {
		t.Fatal(err)
	}
	badInput := w.coldInput(badSnapshot, authority.Sign(badSnapshot), badHelp)
	// The previous one-client check accepted this genuine signature and every
	// unchanged valid current record. It did not verify the signed aggregate.
	if err = w.validateSnapshot(badInput.snapshot, badInput.signature); err != nil {
		t.Fatal(err)
	}
	for slot := range w.roots {
		if err = w.validateAuthorizedRoot(slot); err != nil {
			t.Fatal(err)
		}
		for a := range w.records {
			if err = w.validateRecord(a, slot, w.records[a][slot]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err = verifyColdPublic(badInput, 0); err == nil {
		t.Fatal("valid signature bypassed independent aggregate reconstruction")
	}
}

func TestAllClientsActuallyExecuteColdAudit(t *testing.T) {
	params := pbc.GenerateA(64, 256).String()
	cfg := Config{Capacity: 4, Attributes: 2, Replicate: 1, Revocations: 4, Acquisitions: 4, ColdAuditAllUsers: true}
	result, err := RunCase(params, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateColdAuditEvidence(cfg, result.ColdAudit); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, row := range result.Measurements {
		if row.Operation != "cold_audit" {
			continue
		}
		if row.Count != 1 || row.Mode != "stress_all_clients_replay" || row.Bytes <= 0 {
			t.Fatal("not an actual individual client", row)
		}
		if row.Scheme == "CHARE" && (row.Pairings <= 0 || row.SourceOps <= 0) {
			t.Fatal("reconstruction skipped", row)
		}
		counts[row.Scheme]++
	}
	if counts["CHARE"] != 4 || counts["DH-explicit-list"] != 4 {
		t.Fatal("missing actual client calls", counts)
	}
	e := *result.ColdAudit
	e.Entries = append([]ColdAuditEntry(nil), e.Entries...)
	e.Entries[2] = e.Entries[0]
	if ValidateColdAuditEvidence(cfg, &e) == nil {
		t.Fatal("duplicated evidence passed as another client")
	}
}
