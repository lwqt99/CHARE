package bench

import (
	"errors"

	"example.org/chare/internal/auth"
	"example.org/chare/internal/core"
)

// Public candidate-set changes cannot use the fixed-J update shortcut.
// This explicitly rebuilds the actual cache after a signed batch status event.
// The event describes a synthetic public schedule, not a wall-clock service.
func (w *workload) cohortStress(publisher *auth.Signer) error {
	if w.sequence == ^uint64(0) {
		return errors.New("snapshot sequence overflow")
	}
	var selected []*core.Root
	rows := make([][]*core.Row, len(w.rows))
	var removed int = -1
	var selectedSlots []int
	for slot, root := range w.roots {
		active := slot%2 == 1
		if !active {
			removed = slot
			continue
		}
		selected = append(selected, root)
		selectedSlots = append(selectedSlots, slot)
		for a := range rows {
			rows[a] = append(rows[a], w.rows[a][slot])
		}
	}
	var event []byte
	var signature []byte
	if err := w.measure("CHARE-auth", "batch_status_publish", "stress_changed_cohort", 1, func() (int64, error) {
		var err error
		event, err = w.cohortEvent(selectedSlots)
		if err != nil {
			return 0, err
		}
		signature = publisher.Sign(event)
		if !auth.Verify(publisher.Public(), event, signature) {
			return 0, errors.New("batch status signature failed")
		}
		return int64(len(event) + len(signature)), nil
	}); err != nil {
		return err
	}
	var rebuilt *core.Prepared
	if err := w.measure("CHARE", "batch_expiry_rebuild", "stress_changed_cohort", 1, func() (int64, error) {
		var err error
		rebuilt, err = core.AggregateValidated(w.pp, selected, rows)
		if err != nil {
			return 0, err
		}
		return int64(len(rebuilt.Bytes())), nil
	}); err != nil {
		return err
	}
	_, err := core.Help(rebuilt, removed)
	if err = w.check("removed_slot_not_in_new_cohort", err != nil, "public inactive slot cannot request new-cohort help; old records and ciphertexts remain retained"); err != nil {
		return err
	}
	var snapshot, snapshotSignature []byte
	if err := w.measure("CHARE-auth", "snapshot_publish", "stress_changed_cohort", 1, func() (int64, error) {
		snapshot = cohortSnapshot(rebuilt, w.snapshotCache, w.snapshotSignature, event, signature)
		snapshotSignature = publisher.Sign(snapshot)
		return int64(len(snapshot) + len(snapshotSignature)), nil
	}); err != nil {
		return err
	}
	var sender *core.SenderState
	var context []byte
	if err := w.measure("CHARE", "sender_snapshot_acquisition", "stress_changed_cohort_A", 1, func() (int64, error) {
		var wire []byte
		var err error
		sender, context, wire, err = w.acquireCohortSender(rebuilt, w.snapshotCache, w.snapshotSignature, event, signature, snapshot, snapshotSignature)
		return int64(len(wire)), err
	}); err != nil {
		return err
	}
	w.result.Measurements = append(w.result.Measurements, Measurement{Scheme: "CHARE", Operation: "retained_history_storage", Mode: "stress_branch_publication", Count: 1,
		Bytes: int64(len(event) + len(signature) + len(snapshot) + len(snapshotSignature)), Detail: "no timing sample; actual separate event and complete signed branch snapshot buffers, including repeated parent bytes"})
	return w.exerciseStressTarget("stress_changed_cohort_A", sender, context, rebuilt, selectedSlots)
}

func (w *workload) regrantStress(publisher *auth.Signer) error {
	slot, a := 0, 0
	if w.truth[a][slot] {
		return errors.New("grant-after-denial stress requires an actual refused starting row")
	}
	old := w.records[a][slot]
	var r *issued
	if err := w.measure("CHARE", "regrant_issue", "stress_new_version", 1, func() (int64, error) {
		var err error
		r, err = w.issue(a, slot, true, old.version+1)
		if err != nil {
			return 0, err
		}
		return int64(len(r.publicBytes())), nil
	}); err != nil {
		return err
	}
	if err := w.measure("CHARE", "regrant_install", "stress_new_version", 1, func() (int64, error) {
		if err := w.validateRecord(a, slot, r); err != nil {
			return 0, err
		}
		if err := w.install(a, slot, r); err != nil {
			return 0, err
		}
		w.truth[a][slot] = true
		return int64(len(r.publicBytes())), nil
	}); err != nil {
		return err
	}
	var snapshotSignature []byte
	if err := w.measure("CHARE-auth", "snapshot_publish", "stress_regrant", 1, func() (int64, error) {
		w.snapshotCache = w.snapshot()
		snapshotSignature = publisher.Sign(w.snapshotCache)
		w.snapshotSignature = append([]byte(nil), snapshotSignature...)
		return int64(len(w.snapshotCache) + len(snapshotSignature)), nil
	}); err != nil {
		return err
	}
	if err := w.measure("CHARE", "regrant_refresh", "stress_new_version", 1, func() (int64, error) {
		if err := w.refreshAuthenticated(slot, w.snapshotCache, snapshotSignature); err != nil {
			return 0, err
		}
		h, err := core.Help(w.prepared, slot)
		if err != nil {
			return 0, err
		}
		if err = core.VerifyHelp(w.prepared, h); err != nil {
			return 0, err
		}
		return int64(len(w.snapshotCache) + len(snapshotSignature) + len(h.Bytes())), nil
	}); err != nil {
		return err
	}
	var sender *core.SenderState
	var context []byte
	if err := w.measure("CHARE", "sender_snapshot_acquisition", "stress_regrant_A", 1, func() (int64, error) {
		var wire []byte
		var err error
		sender, context, wire, err = w.acquireSender(w.snapshotCache, w.snapshotSignature)
		return int64(len(wire)), err
	}); err != nil {
		return err
	}
	return w.exerciseStressTarget("stress_regrant_A", sender, context, w.prepared, []int{slot})
}
