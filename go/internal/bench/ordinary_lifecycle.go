package bench

import (
	"bytes"
	"errors"
	"fmt"

	"example.org/chare/internal/auth"
	"example.org/chare/internal/core"
	"example.org/chare/internal/transport"
)

// A separate base, authority and reception secrets are generated. Only the
// native group description is common. Lists are explicit public external inputs;
// their synthetic preparation is recorded outside the registry operations.
func (w *workload) setupOrdinary(parameters string, policies []policySpec) error {
	w.policies = policies
	if err := w.measure("DH-explicit-list", "setup_and_authority_keygen", "cold", 1, func() (int64, error) {
		g := w.ctx.Pairing.NewG1().Rand()
		for tries := 1; g.Is0() && tries < 1024; tries++ {
			g.Rand()
		}
		if g.Is0() {
			return 0, errors.New("DH generator sampling failed")
		}
		var err error
		w.ordinary, err = newOrdinaryRegistry(w.ctx, g, len(w.roots), len(w.rows), parameters, policies)
		if err != nil {
			return 0, err
		}
		return int64(len(w.ordinary.context)), nil
	}); err != nil {
		return err
	}
	d := w.ordinary
	for slot := range d.roots {
		if err := w.measure("DH-explicit-list", "user_keygen", "cold", 1, func() (int64, error) {
			if err := d.keygen(slot); err != nil {
				return 0, err
			}
			return int64(len(auth.Frame("DH/reception-key/v1", number(uint64(slot)), d.roots[slot].Q.Bytes()))), nil
		}); err != nil {
			return err
		}
		if err := w.measure("DH-explicit-list", "root_certify", "cold", 1, func() (int64, error) {
			if err := d.certify(slot); err != nil {
				return 0, err
			}
			return int64(len(d.certs[slot].wire())), nil
		}); err != nil {
			return err
		}
		if err := w.measure("DH-explicit-list", "root_validate", "cold", 1, func() (int64, error) {
			return 0, d.verifyCertificate(slot)
		}); err != nil {
			return err
		}
	}
	if err := w.measure("DH-explicit-list", "registry_publish", "cold", 1, func() (int64, error) {
		return int64(len(d.registryBytes())), nil
	}); err != nil {
		return err
	}
	if err := w.measure("DH-explicit-list", "sender_registry_acquisition", "cold_one_sender", 1, func() (int64, error) {
		wire := append([]byte(nil), d.registryBytes()...)
		for slot := range d.roots {
			if err := d.verifyCertificate(slot); err != nil {
				return 0, err
			}
		}
		return int64(len(wire)), nil
	}); err != nil {
		return err
	}
	if err := w.measure("DH-explicit-list", "transport_cache_setup", "cold", 1, func() (int64, error) {
		client, err := transport.NewCache(d.authority.Public())
		if err != nil {
			return 0, err
		}
		d.transport = transportState{signer: d.authority, client: client, entries: make(map[string]cachedEntry)}
		return int64(len(d.authority.Public())), nil
	}); err != nil {
		return err
	}
	if err := w.publishOrdinaryState("cold"); err != nil {
		return err
	}
	for slot := range d.roots {
		if err := w.acquireOrdinary(slot, "first_acquisition", "cold_own_certificate_and_epoch", true); err != nil {
			return err
		}
	}
	return nil
}

func (w *workload) ordinaryLists(mode string, keep func(int) bool) (map[string][]int, error) {
	lists := make(map[string][]int, len(w.policies))
	err := w.measure("DH-explicit-list", "authorized_list_test_oracle", mode, 1, func() (int64, error) {
		var fields [][]byte
		for _, spec := range w.policies {
			key := ordinaryPolicyKey(spec.lits)
			lists[key] = nil // empty lists are real, authenticated states
			fields = append(fields, []byte(key))
			for slot := range w.roots {
				if (keep == nil || keep(slot)) && w.qualifies(slot, spec.lits) {
					lists[key] = append(lists[key], slot)
					fields = append(fields, number(uint64(slot)))
				}
			}
		}
		return int64(len(auth.Frame("DH/synthetic-list-input/v1", fields...))), nil
	})
	return lists, err
}

func (w *workload) publishOrdinaryState(mode string) error {
	lists, err := w.ordinaryLists(mode, nil)
	if err != nil {
		return err
	}
	return w.measure("DH-explicit-list", "authorization_publish", mode, 1, func() (int64, error) {
		wire, err := w.ordinary.publish(w.sequence, lists)
		return int64(len(wire)), err
	})
}

func (w *workload) acquireOrdinary(slot int, op, mode string, initial bool) error {
	return w.measure("DH-explicit-list", op, mode, 1, func() (int64, error) {
		wire, err := w.ordinary.acquire(slot, w.sequence, initial)
		return int64(len(wire)), err
	})
}

func (w *workload) exerciseOrdinary(name string, policy []core.Literal, retain bool) error {
	return w.exerciseOrdinaryAt(name, policy, retain, w.ordinary, w.sequence, true)
}

func (w *workload) exerciseOrdinaryAt(name string, policy []core.Literal, retain bool,
	d *ordinaryRegistry, sequence uint64, withTransport bool) error {
	v := d.views[ordinaryPolicyKey(policy)]
	var selected []*core.Root
	var context []byte
	if err := w.measure("DH-explicit-list", "sender_authorization_acquisition", name, 1, func() (int64, error) {
		if err := d.verifyView(v, d.epoch, sequence); err != nil {
			return 0, err
		}
		var err error
		selected, err = d.selectedRoots(v)
		if err != nil {
			return 0, err
		}
		context = auth.Frame("DH/authenticated-application-context/v1", d.epoch.signed.wire(), v.signed.wire())
		context = append([]byte(nil), context...)
		return int64(len(context)), nil
	}); err != nil {
		return err
	}
	if len(selected) == 0 {
		return w.check(name+"/DH-empty-list", true, "empty authorization authenticated and charged; anchored KEM has no recipient and is not run")
	}
	var ct *OrdinaryCipher
	var key []byte
	if err := w.measure("DH-explicit-list", "encapsulate", name, 1, func() (int64, error) {
		var err error
		ct, key, err = OrdinaryEnc(w.ctx, d.base.G, selected, context)
		if err != nil {
			return 0, err
		}
		return int64(len(OrdinaryBytes(ct))), nil
	}); err != nil {
		return err
	}
	for _, root := range selected {
		if err := w.measure("DH-explicit-list", "receiver_authorization_verify", name, 1, func() (int64, error) {
			// Already part of the ciphertext context: charge computation here,
			// not a second network transmission of the same context.
			return 0, d.verifyView(v, d.epoch, sequence)
		}); err != nil {
			return err
		}
		var got []byte
		if err := w.measure("DH-explicit-list", "decapsulate", name, 1, func() (int64, error) {
			var err error
			got, err = OrdinaryDec(w.ctx, ct, d.secrets[root.Slot], context)
			return int64(len(got)), err
		}); err != nil {
			return err
		}
		if err := w.check(fmt.Sprintf("%s/DH/slot%d", name, root.Slot), bytes.Equal(got, key), "independent reception secret and authenticated explicit list; no hidden-selection equivalence"); err != nil {
			return err
		}
		if retain {
			d.retained = append(d.retained, ordinaryRetained{ct, append([]byte(nil), key...), root.Slot, append([]byte(nil), context...)})
			retain = false
		}
	}
	if withTransport {
		return w.dhTransport(name, ct, selected, context)
	}
	return nil
}

func (w *workload) ordinaryColdAudit(slot int, mode string, evidence *ColdAuditEvidence) error {
	d := w.ordinary
	return w.measure("DH-explicit-list", "cold_audit", mode, 1, func() (int64, error) {
		fields := [][]byte{d.registryBytes(), d.epoch.signed.wire()}
		for slot := range d.roots {
			if err := d.verifyCertificate(slot); err != nil {
				return 0, err
			}
		}
		for _, key := range d.order {
			v := d.views[key]
			if err := d.verifyView(v, d.epoch, w.sequence); err != nil {
				return 0, err
			}
			if _, err := d.selectedRoots(v); err != nil {
				return 0, err
			}
			fields = append(fields, v.signed.wire())
		}
		copied := append([]byte(nil), auth.Frame("DH/cold-audit/v1", fields...)...)
		evidence.Entries = append(evidence.Entries, ColdAuditEntry{"DH-explicit-list", slot, w.sequence, int64(len(copied))})
		return int64(len(copied)), nil
	})
}

func (w *workload) ordinaryCohortStress() error {
	if w.sequence == ^uint64(0) {
		return errors.New("DH batch epoch overflow")
	}
	lists, err := w.ordinaryLists("stress_changed_cohort", func(slot int) bool { return slot%2 == 1 })
	if err != nil {
		return err
	}
	// Copy immutable keys/views, but authenticate a distinct history namespace.
	// This test branch cannot replace or roll back the main epoch.
	branch := *w.ordinary
	branch.scope = "stress_changed_cohort"
	branch.history = nil
	if err := w.measure("DH-explicit-list", "authorization_publish", "stress_changed_cohort", 1, func() (int64, error) {
		wire, err := branch.publish(w.sequence+1, lists)
		return int64(len(wire)), err
	}); err != nil {
		return err
	}
	for _, key := range branch.order {
		if err := branch.verifyView(branch.views[key], branch.epoch, w.sequence+1); err != nil {
			return err
		}
		for _, member := range branch.views[key].members {
			if member.slot%2 == 0 {
				return errors.New("DH batch retained removed member")
			}
		}
	}
	var total int64
	for _, wire := range branch.history {
		total += int64(len(wire))
	}
	w.result.Measurements = append(w.result.Measurements, Measurement{Scheme: "DH-explicit-list", Operation: "retained_history_storage", Mode: "stress_branch_publication", Bytes: total, Count: 1, Detail: "no timing sample; distinct authenticated branch; shared immutable registry counted in main history only"})
	if err := w.check("DH_changed_cohort_namespace", w.ordinary.verifyEpoch(branch.epoch, w.sequence+1) != nil, "stress history cannot be installed as a main-history epoch"); err != nil {
		return err
	}
	return w.exerciseOrdinaryAt("stress_changed_cohort_A", []core.Literal{{Basis: 0}}, false, &branch, w.sequence+1, false)
}
