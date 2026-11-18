package bench

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	"example.org/chare/internal/auth"
	"example.org/chare/internal/core"
	"example.org/chare/internal/transport"
)

const ProtocolVersion = "CHARE-RATIONAL-BASE-PBC-v1"

// These records are generated objects, not a decoder for untrusted wire points.
type issued struct {
	row      *core.Row
	delivery *Delivery
	version  uint64
	metadata []byte
}

type workload struct {
	ctx               *core.Context
	pp                *core.Params
	result            Result
	roots             []*core.Root
	secrets           []*core.UserSecret
	rootBytes         [][]byte
	rootSignatures    [][]byte
	rootAuthority     []byte
	records           [][]*issued
	rows              [][]*core.Row
	masks             [][]*big.Int // receiver state, populated ONLY by actual capsule opening
	truth             [][]bool     // synthetic correctness oracle; never passed to Aggregate or Help
	issuers           []*auth.Signer
	prepared          *core.Prepared
	history           []*issued
	sequence          uint64
	snapshotCache     []byte
	snapshotSignature []byte
	retained          []retainedTarget
	transport         transportState
	ordinary          *ordinaryRegistry
	policies          []policySpec
	studyMaterial     *serviceMaterial
}

type retainedTarget struct {
	target *core.Target
	ct     *core.Ciphertext
	key    []byte
	slot   int
	help   *core.HelpBundle
	masks  []*big.Int
}

func number(n uint64) []byte { var out [8]byte; binary.BigEndian.PutUint64(out[:], n); return out[:] }

func (w *workload) measure(scheme, op, mode string, count int, fn func() (int64, error)) error {
	before := w.ctx.Stats()
	start := time.Now()
	n, err := fn()
	elapsed := time.Since(start).Nanoseconds()
	after := w.ctx.Stats()
	detail := fmt.Sprintf("executed_target_group_ops=%d;field_samples=%d;bytes_are_serialized_operation_output_or_explicit_acquisition;GC=default", after.TargetOps-before.TargetOps, after.FieldSamples-before.FieldSamples)
	if err != nil {
		detail += ";error=" + err.Error()
	}
	w.result.Measurements = append(w.result.Measurements, Measurement{Scheme: scheme, Operation: op, Mode: mode, DurationNS: elapsed, Bytes: n, SourceOps: after.SourceOps - before.SourceOps, Pairings: after.Pairings - before.Pairings, Count: count, Detail: detail})
	return err
}

func (w *workload) check(name string, ok bool, detail string) error {
	w.result.Checks = append(w.result.Checks, Check{Name: name, Passed: ok, Detail: detail})
	if !ok {
		return fmt.Errorf("functional check failed: %s: %s", name, detail)
	}
	return nil
}

func (r *issued) publicBytes() []byte {
	return auth.Frame("CHARE/issued/v1", r.metadata, r.row.Bytes(), DeliveryBytes(r.delivery))
}

func (w *workload) snapshot() []byte {
	fields := [][]byte{[]byte(ProtocolVersion), w.pp.Bytes(), number(w.sequence), number(uint64(len(w.roots))), number(uint64(len(w.rows)))}
	if w.prepared != nil {
		fields = append(fields, w.prepared.VerifierBytes())
		fields = append(fields, w.prepared.SenderBytes())
	}
	for _, b := range w.rootBytes {
		fields = append(fields, b)
	}
	for _, pub := range w.issuers {
		fields = append(fields, pub.Public())
	}
	for a := range w.records {
		for _, r := range w.records[a] {
			fields = append(fields, r.publicBytes())
		}
	}
	return auth.Frame("CHARE/full-current-snapshot/v2", fields...)
}

func (w *workload) issue(a, slot int, y bool, version uint64) (*issued, error) {
	r, delta, err := core.Issue(w.pp, w.roots[slot], y)
	if err != nil {
		return nil, err
	}
	// Qualification y and private delta never enter public metadata.
	meta := w.recordMetadata(a, slot, version, r)
	d, err := SealScalar(w.ctx, w.pp.G, w.roots[slot].Q, delta, meta, w.issuers[a])
	if err != nil {
		return nil, err
	}
	return &issued{row: r, delivery: d, version: version, metadata: meta}, nil
}

func (w *workload) recordMetadata(a, slot int, version uint64, row *core.Row) []byte {
	return auth.Frame("CHARE/issuance-context/v1", []byte(ProtocolVersion), w.pp.Bytes(), number(uint64(a)), number(uint64(slot)), number(version), number(1), number(^uint64(0)), w.rootBytes[slot], row.Bytes())
}

func (w *workload) validateRecord(a, slot int, r *issued) error {
	if r == nil || r.row.Slot != slot {
		return errors.New("wrong record slot")
	}
	if err := core.ValidateRow(w.pp, w.roots[slot], r.row); err != nil {
		return err
	}
	expected := w.recordMetadata(a, slot, r.version, r.row)
	if !bytes.Equal(expected, r.metadata) {
		return errors.New("record metadata differs from actual row/slot/issuer/version")
	}
	return ValidateDelivery(w.ctx, w.pp.G, w.roots[slot].Q, r.delivery, expected, w.issuers[a].Public())
}

// Installation is public state, independent of hidden scalar decoding. Exact
// replay is idempotent; an old or conflicting version is rejected.
func (w *workload) install(a, slot int, r *issued) error {
	old := w.records[a][slot]
	if r.version <= old.version {
		if r.version == old.version && bytes.Equal(r.publicBytes(), old.publicBytes()) {
			return nil
		}
		return errors.New("record rollback or conflicting immutable version")
	}
	if w.sequence == ^uint64(0) {
		return errors.New("snapshot sequence overflow")
	}
	if e := w.prepared.UpdateRow(a, slot, r.row); e != nil {
		return e
	}
	w.records[a][slot] = r
	w.rows[a][slot] = r.row
	w.history = append(w.history, r)
	w.sequence++
	return nil
}

func (w *workload) refresh(slot int) error {
	// A later namespace may fail local signature/binding/canonical decoding.
	// Keep every old value until all selected deliveries have opened correctly.
	staged := make([]*big.Int, len(w.records))
	for a := range w.records {
		r := w.records[a][slot]
		delta, err := OpenScalar(w.ctx, w.pp.G, w.secrets[slot].Z, r.delivery, r.metadata, w.issuers[a].Public())
		if err != nil {
			return err
		}
		staged[a] = delta
	}
	for a, delta := range staged {
		w.masks[a][slot] = delta
	}
	return nil
}

func (w *workload) ownMasks(slot int) []*big.Int {
	out := make([]*big.Int, len(w.masks))
	for a := range out {
		if w.masks[a][slot] != nil {
			out[a] = new(big.Int).Set(w.masks[a][slot])
		}
	}
	return out
}

func (w *workload) qualifies(slot int, policy []core.Literal) bool {
	for _, l := range policy {
		b := w.truth[l.Basis][slot]
		if l.Negative {
			b = !b
		}
		if !b {
			return false
		}
	}
	return true
}

func (w *workload) exercisePolicy(name string, policy []core.Literal, retain bool) error {
	retainDH := retain
	var target *core.Target
	var ct *core.Ciphertext
	var expected []byte
	context := w.snapshotCache
	if len(context) == 0 {
		return errors.New("no published snapshot")
	}
	var sender *core.SenderState
	if err := w.measure("CHARE", "sender_snapshot_acquisition", name, 1, func() (int64, error) {
		var wire []byte
		var err error
		sender, context, wire, err = w.acquireSender(w.snapshotCache, w.snapshotSignature)
		return int64(len(wire)), err
	}); err != nil {
		return err
	}
	if err := w.measure("CHARE", "prepare_policy", name, 1, func() (int64, error) {
		var err error
		target, err = sender.Prepare(policy, context)
		if err != nil {
			return 0, err
		}
		return int64(len(target.Context)), nil
	}); err != nil {
		return err
	}
	if err := w.measure("CHARE", "encapsulate", name, 1, func() (int64, error) {
		var err error
		ct, expected, err = core.Encapsulate(target)
		if err != nil {
			return 0, err
		}
		return int64(len(ct.Bytes())), nil
	}); err != nil {
		return err
	}
	// The two-point algebraic header is also recorded separately, with no claim
	// that the full context or actual header processing is free.
	w.result.Measurements = append(w.result.Measurements, Measurement{Scheme: "CHARE", Operation: "cipher_core_bytes", Mode: name, Bytes: int64(len(ct.C0.Bytes()) + len(ct.C1.Bytes())), Count: 1, Detail: "actual serialization length only; no timing sample"})
	for slot := range w.roots {
		var help *core.HelpBundle
		var got []byte
		if err := w.measure("CHARE", "help_generate", name, 1, func() (int64, error) {
			var err error
			help, err = core.Help(w.prepared, slot)
			if err != nil {
				return 0, err
			}
			return int64(len(help.Bytes())), nil
		}); err != nil {
			return err
		}
		if err := w.measure("CHARE", "help_verify", name, 1, func() (int64, error) { return 0, core.VerifyHelp(w.prepared, help) }); err != nil {
			return err
		}
		if err := w.measure("CHARE", "decapsulate", name, 1, func() (int64, error) {
			var err error
			got, err = core.Decapsulate(target, ct, w.secrets[slot], w.ownMasks(slot), help)
			return int64(len(got)), err
		}); err != nil {
			return err
		}
		want := w.qualifies(slot, policy)
		if err := w.check(fmt.Sprintf("%s/slot%d", name, slot), bytes.Equal(got, expected) == want, "synthetic qualification oracle; equality is a functional observation, not a security proof"); err != nil {
			return err
		}
		if retain && want {
			w.retained = append(w.retained, retainedTarget{target, ct, append([]byte(nil), expected...), slot, help, w.ownMasks(slot)})
			retain = false
		}
	}
	if err := w.chareTransport(name, target, ct); err != nil {
		return err
	}
	return w.exerciseOrdinary(name, policy, retainDH)
}

// RunCase returns completed measurements even on error. Setup, issuance,
// signatures, pairing checks, aggregate preparation and acquisition execute;
// no formula is substituted for a timed group operation.
func RunCase(params string, cfg Config) (result Result, err error) {
	w := &workload{}
	defer func() { result = w.result }()
	if cfg.Capacity < 2 || cfg.Attributes < 1 || cfg.Attributes > 64 || cfg.Revocations < 0 || cfg.Acquisitions < 0 {
		return result, errors.New("unsupported workload dimensions")
	}
	w.result.Workload = &WorkloadEvidence{
		Schedule: WorkloadSchedule, InitialActiveQualifications: ActiveQualificationCount(cfg.Capacity, cfg.Attributes),
		RequestedRevocations: cfg.Revocations, RequestedAcquisitions: cfg.Acquisitions,
		Events: make([]RevocationEvent, 0),
	}
	revocationPlan, err := activeRevocationPlan(cfg.Capacity, cfg.Attributes, cfg.Revocations)
	if err != nil {
		return result, err
	}
	nativeStart := time.Now()
	w.ctx, err = core.NewContext(params)
	w.result.NativeContext = &NativeContextEvidence{DurationNS: time.Since(nativeStart).Nanoseconds(), Status: "failed"}
	if err != nil {
		w.result.NativeContext.Error = err.Error()
		return result, err
	}
	admission := w.ctx.NativeAdmission
	w.result.NativeContext.Status = "passed"
	w.result.NativeContext.Admission = &admission
	n, m := cfg.Capacity, cfg.Attributes
	if err = w.measure("CHARE", "setup", "cold", 1, func() (int64, error) {
		w.pp, err = core.Setup(w.ctx, n)
		if err != nil {
			return 0, err
		}
		return int64(len(w.pp.Bytes())), nil
	}); err != nil {
		return result, err
	}
	w.roots = make([]*core.Root, n)
	w.secrets = make([]*core.UserSecret, n)
	w.rootBytes = make([][]byte, n)
	w.rows = make([][]*core.Row, m)
	w.records = make([][]*issued, m)
	w.masks = make([][]*big.Int, m)
	w.truth = make([][]bool, m)
	w.issuers = make([]*auth.Signer, m)
	var enrollment *auth.Signer
	if err = w.measure("CHARE-auth", "authority_keygen", "cold", m+1, func() (int64, error) {
		enrollment, err = auth.Generate()
		if err != nil {
			return 0, err
		}
		size := len(enrollment.Public())
		for a := range w.issuers {
			w.issuers[a], err = auth.Generate()
			if err != nil {
				return 0, err
			}
			size += len(w.issuers[a].Public())
		}
		return int64(size), nil
	}); err != nil {
		return result, err
	}
	if err = w.measure("CHARE-auth", "transport_cache_setup", "cold", 1, func() (int64, error) {
		client, e := transport.NewCache(enrollment.Public())
		if e != nil {
			return 0, e
		}
		w.transport = transportState{signer: enrollment, client: client, entries: make(map[string]cachedEntry)}
		return int64(len(enrollment.Public())), nil
	}); err != nil {
		return result, err
	}
	w.rootAuthority = append([]byte(nil), enrollment.Public()...)
	w.rootSignatures = make([][]byte, n)
	for slot := 0; slot < n; slot++ {
		if err = w.measure("CHARE", "user_keygen", "cold", 1, func() (int64, error) {
			w.roots[slot], w.secrets[slot], err = core.UserKeyGen(w.pp, slot)
			if err != nil {
				return 0, err
			}
			return int64(len(w.roots[slot].Bytes())), nil
		}); err != nil {
			return result, err
		}
		if err = w.measure("CHARE-auth", "root_certify", "cold", 1, func() (int64, error) {
			msg := w.rootMessage(slot)
			sig := enrollment.Sign(msg)
			if !auth.Verify(enrollment.Public(), msg, sig) {
				return 0, errors.New("root signature self-check")
			}
			w.rootBytes[slot] = auth.Frame("CHARE/certified-root/v1", msg, sig, enrollment.Public())
			w.rootSignatures[slot] = append([]byte(nil), sig...)
			return int64(len(w.rootBytes[slot])), nil
		}); err != nil {
			return result, err
		}
		if err = w.measure("CHARE", "root_validate", "cold", 1, func() (int64, error) { return 0, w.validateAuthorizedRoot(slot) }); err != nil {
			return result, err
		}
	}
	for a := 0; a < m; a++ {
		w.rows[a] = make([]*core.Row, n)
		w.records[a] = make([]*issued, n)
		w.masks[a] = make([]*big.Int, n)
		w.truth[a] = make([]bool, n)
		for slot := 0; slot < n; slot++ {
			// Two-attribute instances contain all four classes when N>=4.
			w.truth[a][slot] = syntheticQualification(slot, a)
			if err = w.measure("CHARE", "certify_and_deliver", "cold", 1, func() (int64, error) {
				r, e := w.issue(a, slot, w.truth[a][slot], 1)
				if e != nil {
					return 0, e
				}
				w.records[a][slot] = r
				w.rows[a][slot] = r.row
				w.history = append(w.history, r)
				return int64(len(r.publicBytes())), nil
			}); err != nil {
				return result, err
			}
			if err = w.measure("CHARE", "record_validate", "cold", 1, func() (int64, error) { return 0, w.validateRecord(a, slot, w.records[a][slot]) }); err != nil {
				return result, err
			}
		}
	}
	if err = w.measure("CHARE", "aggregate", "cold_after_full_validation", 1, func() (int64, error) {
		w.prepared, err = core.AggregateValidated(w.pp, w.roots, w.rows)
		if err != nil {
			return 0, err
		}
		return int64(len(w.prepared.Bytes())), nil
	}); err != nil {
		return result, err
	}
	var snapshot []byte
	var snapshotSig []byte
	if err = w.measure("CHARE-auth", "snapshot_publish", "cold", 1, func() (int64, error) {
		snapshot = w.snapshot()
		w.snapshotCache = snapshot
		snapshotSig = enrollment.Sign(snapshot)
		w.snapshotSignature = append([]byte(nil), snapshotSig...)
		return int64(len(snapshot) + len(snapshotSig)), nil
	}); err != nil {
		return result, err
	}
	for slot := 0; slot < n; slot++ {
		if err = w.measure("CHARE", "first_acquisition", "cold_full_manifest", 1, func() (int64, error) {
			if e := w.refreshAuthenticated(slot, snapshot, snapshotSig); e != nil {
				return 0, e
			}
			h, e := core.Help(w.prepared, slot)
			if e != nil {
				return 0, e
			}
			if e = core.VerifyHelp(w.prepared, h); e != nil {
				return 0, e
			}
			payload := auth.Frame("CHARE/acquisition/v1", snapshot, snapshotSig, h.Bytes())
			copied := append([]byte(nil), payload...)
			return int64(len(copied)), nil
		}); err != nil {
			return result, err
		}
	}
	if cfg.PaperStudy {
		if err = w.runPaperStudy(cfg); err != nil {
			return result, err
		}
	}
	policies := []policySpec{{"A", []core.Literal{{Basis: 0}}}, {"not_A", []core.Literal{{Basis: 0, Negative: true}}}}
	if m >= 2 {
		policies = append(policies, policySpec{"B", []core.Literal{{Basis: 1}}}, policySpec{"A_and_B", []core.Literal{{Basis: 0}, {Basis: 1}}})
	}
	if m > 2 {
		all := make([]core.Literal, m)
		for a := range all {
			all[a] = core.Literal{Basis: a}
		}
		policies = append(policies, policySpec{"all_attributes", all})
	}
	if err = w.setupOrdinary(params, policies); err != nil {
		return result, err
	}
	for _, p := range policies {
		if err = w.exercisePolicy(p.name, p.lits, true); err != nil {
			return result, err
		}
	}
	acquired := 0
	acquire := func() error {
		// Selection depends only on the already published transcript. This is
		// a specified interleaved schedule, not a model of real user arrivals.
		slot := (acquired*7 + cfg.Replicate + int(w.sequence%uint64(n)) + len(snapshot)%n) % n
		if err = w.measure("CHARE", "refresh", "warm_full_manifest", 1, func() (int64, error) {
			if e := w.refreshAuthenticated(slot, snapshot, snapshotSig); e != nil {
				return 0, e
			}
			h, e := core.Help(w.prepared, slot)
			if e != nil {
				return 0, e
			}
			if e = core.VerifyHelp(w.prepared, h); e != nil {
				return 0, e
			}
			return int64(len(auth.Frame("CHARE/refresh/v1", snapshot, snapshotSig, h.Bytes()))), nil
		}); err != nil {
			return err
		}
		if err = w.acquireOrdinary(slot, "refresh", "warm_current_epoch", false); err != nil {
			return err
		}
		acquired++
		w.result.Workload.CompletedAcquisitions = acquired
		return nil
	}
	// Offline canonical denial: holder does not open the new capsule until an
	// acquisition. All old rows, masks, helpers and ciphertexts remain retained.
	for step, selection := range revocationPlan {
		a, slot := selection.attribute, selection.slot
		if !w.truth[a][slot] {
			return result, errors.New("effective revocation selected an already denied qualification")
		}
		old := w.records[a][slot]
		w.result.Workload.Events = append(w.result.Workload.Events, RevocationEvent{
			Step: step + 1, Attribute: a, Slot: slot, Before: w.truth[a][slot],
			After: w.truth[a][slot], PreviousVersion: old.version,
		})
		event := &w.result.Workload.Events[len(w.result.Workload.Events)-1]
		var replacement *issued
		if err = w.measure("CHARE", "offline_denial_issue", "update", 1, func() (int64, error) {
			replacement, err = w.issue(a, slot, false, old.version+1)
			if err != nil {
				return 0, err
			}
			return int64(len(replacement.publicBytes())), nil
		}); err != nil {
			return result, err
		}
		if err = w.measure("CHARE", "offline_denial_validate", "update", 1, func() (int64, error) { return 0, w.validateRecord(a, slot, replacement) }); err != nil {
			return result, err
		}
		if err = w.measure("CHARE", "moment_row_update", "warm", 1, func() (int64, error) {
			if e := w.install(a, slot, replacement); e != nil {
				return 0, e
			}
			w.truth[a][slot] = false
			event.After = w.truth[a][slot]
			event.InstalledVersion = replacement.version
			event.Sequence = w.sequence
			event.CHAREInstalled = true
			return int64(len(replacement.publicBytes())), nil
		}); err != nil {
			return result, err
		}
		if err = w.measure("CHARE-auth", "snapshot_publish", "update", 1, func() (int64, error) {
			snapshot = w.snapshot()
			w.snapshotCache = snapshot
			snapshotSig = enrollment.Sign(snapshot)
			w.snapshotSignature = append([]byte(nil), snapshotSig...)
			return int64(len(snapshot) + len(snapshotSig)), nil
		}); err != nil {
			return result, err
		}
		if e := w.install(a, slot, old); e == nil {
			return result, errors.New("rollback unexpectedly accepted")
		}
		if e := w.install(a, slot, replacement); e != nil {
			return result, errors.New("exact replay not idempotent")
		}
		if err = w.publishOrdinaryState("update"); err != nil {
			return result, err
		}
		event.BaselinePublished = true
		w.result.Workload.CompletedEffectiveRevocations++
		if err = w.check(fmt.Sprintf("effective_revocation_%d", step+1), event.Before && !event.After,
			fmt.Sprintf("synthetic input attribute=%d slot=%d; actual 1-to-0 transition installed in CHARE and published by independent DH", a, slot)); err != nil {
			return result, err
		}
		limit := int(int64(step+1) * int64(cfg.Acquisitions) / int64(cfg.Revocations))
		for acquired < limit {
			if e := acquire(); e != nil {
				return result, e
			}
		}

	}
	for acquired < cfg.Acquisitions {
		if e := acquire(); e != nil {
			return result, e
		}
	}
	if err = ValidateWorkloadEvidence(cfg, w.result.Workload); err != nil {
		return result, err
	}
	if err = w.check("main_workload_completed", true, "requested number of distinct 1-to-0 qualifications and paired acquisitions completed; later stress branches are separate"); err != nil {
		return result, err
	}
	// End-of-workload all-user catch-up is a separately charged stress boundary.
	for slot := 0; slot < n; slot++ {
		if err = w.measure("CHARE", "offline_catchup", "stress_all_users", 1, func() (int64, error) {
			if e := w.refreshAuthenticated(slot, snapshot, snapshotSig); e != nil {
				return 0, e
			}
			h, e := core.Help(w.prepared, slot)
			if e != nil {
				return 0, e
			}
			if e = core.VerifyHelp(w.prepared, h); e != nil {
				return 0, e
			}
			return int64(len(snapshot) + len(snapshotSig) + len(h.Bytes())), nil
		}); err != nil {
			return result, err
		}
	}
	for _, p := range policies {
		if err = w.exercisePolicy("after_updates_"+p.name, p.lits, false); err != nil {
			return result, err
		}
	}
	for slot := range w.roots {
		if err = w.acquireOrdinary(slot, "offline_catchup", "stress_all_users_current_epoch", false); err != nil {
			return result, err
		}
	}
	if err = w.ordinary.verifyRetained(); err != nil {
		return result, err
	}
	if err = w.check("DH_retained_old_state", true, "all retained old ciphertexts recovered using own old reception secrets; no retroactive revocation"); err != nil {
		return result, err
	}
	for k, old := range w.retained {
		got, e := core.Decapsulate(old.target, old.ct, w.secrets[old.slot], old.masks, old.help)
		if e != nil {
			return result, e
		}
		if err = w.check(fmt.Sprintf("retained_old_state_%d", k), bytes.Equal(got, old.key), "old authorized keys remain recoverable; no retroactive revocation claim"); err != nil {
			return result, err
		}
	}
	// A fresh verifier replays the public history for every requested client.
	if err = w.coldAudits(cfg, snapshot, snapshotSig); err != nil {
		return result, err
	}
	var historyBytes int64
	if err = w.cohortStress(enrollment); err != nil {
		return result, err
	}
	if err = w.ordinaryCohortStress(); err != nil {
		return result, err
	}
	if err = w.regrantStress(enrollment); err != nil {
		return result, err
	}
	if err = w.publishOrdinaryState("stress_regrant"); err != nil {
		return result, err
	}
	if err = w.acquireOrdinary(0, "regrant_refresh", "stress_new_version", false); err != nil {
		return result, err
	}
	if err = w.exerciseOrdinary("stress_regrant_A", []core.Literal{{Basis: 0}}, false); err != nil {
		return result, err
	}
	for _, r := range w.history {
		historyBytes += int64(len(r.publicBytes()))
	}
	w.result.Measurements = append(w.result.Measurements, Measurement{Scheme: "CHARE", Operation: "retained_history_storage", Mode: "actual_serialized_records", Bytes: historyBytes, Count: 1, Detail: "no timing sample; actual public record payload only; private scalar states never exported; immutable history retained"})
	w.result.Measurements = append(w.result.Measurements,
		Measurement{Scheme: "DH-explicit-list", Operation: "retained_history_storage", Mode: "actual_certificates_and_publications", Bytes: w.ordinary.retainedBytes(), Count: 1, Detail: "no timing sample; certificate wires and immutable main-history publication buffers; private secrets and map overhead excluded"})
	w.transportStorage("CHARE", &w.transport)
	w.transportStorage("DH-explicit-list", &w.ordinary.transport)
	return result, nil
}
