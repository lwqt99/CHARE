package bench

import (
	"bytes"
	"errors"
	"strconv"

	"example.org/chare/internal/auth"
	"example.org/chare/internal/core"
)

// A branch is a separate, explicitly selected synthetic history. Its signature
// authenticates the rebuilt sender inputs; it does not prove freshness, correct
// aggregation, or that this branch should replace the main history.
func (w *workload) cohortEvent(slots []int) ([]byte, error) {
	if w.sequence == ^uint64(0) {
		return nil, errors.New("snapshot sequence overflow")
	}
	active := make(map[int]bool, len(slots))
	previous := -1
	for _, slot := range slots {
		if slot <= previous || slot < 0 || slot >= len(w.roots) {
			return nil, errors.New("invalid or unordered cohort slots")
		}
		active[slot], previous = true, slot
	}
	fields := [][]byte{[]byte(ProtocolVersion), number(w.sequence + 1), []byte("synthetic-public-batch-expiry")}
	for slot := range w.roots {
		flag := byte(0)
		if active[slot] {
			flag = 1
		}
		fields = append(fields, number(uint64(slot)), []byte{flag})
	}
	return auth.Frame("CHARE/public-status-event/v1", fields...), nil
}

func cohortSnapshot(prepared *core.Prepared, parent, parentSignature, event, eventSignature []byte) []byte {
	return auth.Frame("CHARE/cohort-sender-snapshot/v1", []byte(ProtocolVersion),
		parent, parentSignature, event, eventSignature, prepared.VerifierBytes(), prepared.SenderBytes())
}

func (w *workload) acquireCohortSender(prepared *core.Prepared, parent, parentSignature,
	event, eventSignature, snapshot, signature []byte) (*core.SenderState, []byte, []byte, error) {
	// Authenticate all externally supplied envelopes before point copying.
	for _, signed := range [][2][]byte{{parent, parentSignature}, {event, eventSignature}, {snapshot, signature}} {
		if err := w.validateSnapshot(signed[0], signed[1]); err != nil {
			return nil, nil, nil, err
		}
	}
	if prepared == nil || prepared.Params != w.pp || !bytes.Equal(parent, w.snapshot()) {
		return nil, nil, nil, errors.New("cohort parent or parameters differ from selected public state")
	}
	expectedEvent, err := w.cohortEvent(prepared.Slots)
	if err != nil {
		return nil, nil, nil, err
	}
	if !bytes.Equal(event, expectedEvent) ||
		!bytes.Equal(snapshot, cohortSnapshot(prepared, parent, parentSignature, event, eventSignature)) {
		return nil, nil, nil, errors.New("cohort event or signed sender material mismatch")
	}
	sender, err := prepared.CopySender()
	if err != nil {
		return nil, nil, nil, err
	}
	if !bytes.Equal(sender.Bytes(), prepared.SenderBytes()) {
		return nil, nil, nil, errors.New("cohort sender copy differs from authenticated material")
	}
	context := append([]byte(nil), snapshot...)
	return sender, context, auth.Frame("CHARE/sender-acquisition/v1", context, signature), nil
}

// Both stress paths use an authenticated, independently copied public sender.
// Help still comes from the actual rebuilt/updated public directory.
func (w *workload) exerciseStressTarget(name string, sender *core.SenderState, context []byte,
	prepared *core.Prepared, slots []int) error {
	var target *core.Target
	var ct *core.Ciphertext
	var key []byte
	policy := []core.Literal{{Basis: 0}}
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
		ct, key, err = core.Encapsulate(target)
		if err != nil {
			return 0, err
		}
		return int64(len(ct.Bytes())), nil
	}); err != nil {
		return err
	}
	for _, slot := range slots {
		var help *core.HelpBundle
		if err := w.measure("CHARE", "help_generate", name, 1, func() (int64, error) {
			var err error
			help, err = core.Help(prepared, slot)
			if err != nil {
				return 0, err
			}
			return int64(len(help.Bytes())), nil
		}); err != nil {
			return err
		}
		if err := w.measure("CHARE", "help_verify", name, 1, func() (int64, error) {
			return 0, core.VerifyHelp(prepared, help)
		}); err != nil {
			return err
		}
		var got []byte
		if err := w.measure("CHARE", "decapsulate", name, 1, func() (int64, error) {
			var err error
			got, err = core.Decapsulate(target, ct, w.secrets[slot], w.ownMasks(slot), help)
			return int64(len(got)), err
		}); err != nil {
			return err
		}
		if err := w.check(name+"/slot"+strconv.Itoa(slot), bytes.Equal(got, key) == w.qualifies(slot, policy),
			"authenticated public-only stress sender; actual retained receiver state; functional observation only"); err != nil {
			return err
		}
	}
	if w.result.Study != nil {
		return w.chareTransportAt(name, target, ct, prepared)
	}
	return nil
}
