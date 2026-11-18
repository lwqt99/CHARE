package bench

import (
	"bytes"
	"errors"
	"fmt"

	"example.org/chare/internal/core"
)

const StudySchema = "chare-native-study-v1"

func ValidateStudyEvidence(cfg Config, s *StudyEvidence) error {
	if !cfg.PaperStudy {
		return nil
	}
	if s == nil || s.Schema != StudySchema || !s.HelperEqual || !s.OwnHelperEqual || !s.OldStateUnchanged || !s.ChangedCohortRejected || len(s.Services) != 2 {
		return errors.New("incomplete native paper-study evidence")
	}
	for i, kind := range []string{"tree", "cycle"} {
		x := s.Services[i]
		edges := cfg.Capacity - 1 + i
		if x.Graph != kind || x.Participants != cfg.Capacity || x.Directions != 2 || x.Edges != edges || x.Contributions != 2*cfg.Capacity || x.PadDeliveries != 2*edges || !x.AggregateEqual || !x.StrictPrefixProtected || x.OnePadProtected != (kind == "cycle") || x.CutPadsProtected || !x.RecoveryKeyEqual {
			return errors.New("invalid native service evidence")
		}
	}
	return nil
}

type StudyEvidence struct {
	Schema                string            `json:"schema"`
	ComparisonOrder       []string          `json:"comparison_order"`
	HelperEqual           bool              `json:"helper_equal"`
	OwnHelperEqual        bool              `json:"own_helper_equal"`
	OldStateUnchanged     bool              `json:"old_state_unchanged"`
	ChangedCohortRejected bool              `json:"changed_cohort_rejected"`
	Services              []ServiceEvidence `json:"services"`
}

// Paired methods use the same actual issued row, roots and immutable old state.
// These separate measurements are component ablations, never added a second
// time to the legacy end-to-end lifecycle. Full authentication/issuance and
// setup costs are retained as separately named study observations.
func (w *workload) runPaperStudy(cfg Config) error {
	if len(w.roots) < 4 {
		return errors.New("paper study requires at least four holders")
	}
	w.result.Study = &StudyEvidence{Schema: StudySchema}
	s := w.result.Study
	changed, receiver := 1, len(w.roots)-1
	var old, cached, rebuilt *core.Prepared
	if err := w.measure("CHARE-study", "study_setup", "helper_comparison", 2, func() (int64, error) {
		var err error
		old, err = core.AggregateValidated(w.pp, w.roots, w.rows)
		if err != nil {
			return 0, err
		}
		cached, err = core.AggregateValidated(w.pp, w.roots, w.rows)
		return 0, err
	}); err != nil {
		return err
	}
	previous, err := core.Help(old, receiver)
	if err != nil {
		return err
	}
	if err = core.VerifyHelp(old, previous); err != nil {
		return err
	}
	own, err := core.Help(old, changed)
	if err != nil {
		return err
	}
	oldBytes, oldHelp := old.ContextBytes(), previous.Bytes()
	var replacement *issued
	if err = w.measure("CHARE-study", "issue_and_authenticate", "shared_update_input", 1, func() (int64, error) {
		var e error
		replacement, e = w.issue(0, changed, false, w.records[0][changed].version+1)
		if e != nil {
			return 0, e
		}
		return int64(len(replacement.publicBytes())), nil
	}); err != nil {
		return err
	}
	if err = w.measure("CHARE-study", "validate_update", "shared_directory_input", 1, func() (int64, error) {
		return 0, w.validateRecord(0, changed, replacement)
	}); err != nil {
		return err
	}
	nextRows := make([][]*core.Row, len(w.rows))
	for b := range w.rows {
		nextRows[b] = append([]*core.Row(nil), w.rows[b]...)
	}
	nextRows[0][changed] = replacement.row
	fullDirectory := func() error {
		return w.measure("CHARE-rebuild", "directory_update", "same_cohort", 1, func() (int64, error) {
			var e error
			rebuilt, e = core.AggregateValidated(w.pp, w.roots, nextRows)
			return 0, e
		})
	}
	cachedDirectory := func() error {
		return w.measure("CHARE-delta", "directory_update", "same_cohort", 1, func() (int64, error) {
			return 0, cached.UpdateRow(0, changed, replacement.row)
		})
	}
	if cfg.Replicate%2 == 1 {
		s.ComparisonOrder = []string{"rebuild", "delta"}
		if err = fullDirectory(); err == nil {
			err = cachedDirectory()
		}
	} else {
		s.ComparisonOrder = []string{"delta", "rebuild"}
		if err = cachedDirectory(); err == nil {
			err = fullDirectory()
		}
	}
	if err != nil {
		return err
	}
	var delta, full *core.HelpBundle
	fullHelper := func() error {
		return w.measure("CHARE-rebuild", "client_helper_update", "same_cohort", 1, func() (int64, error) {
			if e := core.ValidateRow(w.pp, w.roots[changed], replacement.row); e != nil {
				return 0, e
			}
			var e error
			full, e = core.Help(cached, receiver)
			if e != nil {
				return 0, e
			}
			return int64(len(full.Bytes())), nil
		})
	}
	deltaHelper := func() error {
		return w.measure("CHARE-delta", "client_helper_update", "same_cohort", 1, func() (int64, error) {
			var e error
			delta, e = core.HelpDelta(old, previous, 0, changed, replacement.row)
			if e != nil {
				return 0, e
			}
			return int64(len(delta.Bytes())), nil
		})
	}
	if cfg.Replicate%2 == 1 {
		if err = fullHelper(); err == nil {
			err = deltaHelper()
		}
	} else {
		if err = deltaHelper(); err == nil {
			err = fullHelper()
		}
	}
	if err != nil {
		return err
	}
	s.HelperEqual = bytes.Equal(delta.Bytes(), full.Bytes())
	if err = w.check("native_study/helper_delta_exact", s.HelperEqual, "same row, old helper, full N-1 checks, exact full helper bytes"); err != nil {
		return err
	}
	if err = core.VerifyHelp(cached, delta); err != nil {
		return err
	}
	fresh, err := core.Help(rebuilt, receiver)
	if err != nil {
		return err
	}
	if err = w.check("native_study/directory_update_equivalence", helpPointsEqual(fresh, full), "rebuild and cache use the same new records; immutable context encodings are not conflated"); err != nil {
		return err
	}
	ownNext, err := core.HelpDelta(old, own, 0, changed, replacement.row)
	if err != nil {
		return err
	}
	s.OwnHelperEqual = own.Parts[1].Equals(ownNext.Parts[1])
	if err = w.check("native_study/own_delta_zero", s.OwnHelperEqual, "own-slot decision does not change the off-slot help"); err != nil {
		return err
	}
	s.OldStateUnchanged = bytes.Equal(oldBytes, old.ContextBytes()) && bytes.Equal(oldHelp, previous.Bytes())
	if err = w.check("native_study/old_state_retained", s.OldStateUnchanged, "paired algorithms did not mutate retained previous helper or aggregate"); err != nil {
		return err
	}
	// With the four-class grid and N divisible by four the last holder has A.
	target, err := core.PrepareTarget(cached, []core.Literal{{Basis: 0}})
	if err != nil {
		return err
	}
	ct, key, err := core.Encapsulate(target)
	if err != nil {
		return err
	}
	got, err := core.Decapsulate(target, ct, w.secrets[receiver], w.ownMasks(receiver), delta)
	if err != nil {
		return err
	}
	if err = w.check("native_study/delta_decapsulation", bytes.Equal(got, key) == w.truth[0][receiver], "actual PBC decapsulation with staged helper and actual old receiver masks"); err != nil {
		return err
	}
	if _, e := core.Decapsulate(target, ct, w.secrets[receiver], w.ownMasks(receiver), previous); e == nil {
		return errors.New("study accepted old-version helper")
	}
	// Changing J is explicitly a rebuild boundary, not an incremental shortcut.
	subRows := make([][]*core.Row, len(nextRows))
	for b := range nextRows {
		subRows[b] = nextRows[b][:len(w.roots)-1]
	}
	var sub *core.Prepared
	if err = w.measure("CHARE-rebuild", "directory_update", "changed_cohort", 1, func() (int64, error) {
		var e error
		sub, e = core.AggregateValidated(w.pp, w.roots[:len(w.roots)-1], subRows)
		return 0, e
	}); err != nil {
		return err
	}
	_, bad := core.HelpDelta(sub, previous, 0, changed, replacement.row)
	s.ChangedCohortRejected = bad != nil
	if err = w.check("native_study/changed_cohort_requires_rebuild", s.ChangedCohortRejected, "old helper cannot be relabeled onto a different candidate set"); err != nil {
		return err
	}
	for _, kind := range []string{"tree", "cycle"} {
		if err = w.studyService(cfg, kind); err != nil {
			return fmt.Errorf("service %s: %w", kind, err)
		}
	}
	return nil
}

func helpPointsEqual(a, b *core.HelpBundle) bool {
	if a == nil || b == nil || len(a.Parts) != len(b.Parts) || !a.R.Equals(b.R) || !a.Gamma.Equals(b.Gamma) || !a.W.Equals(b.W) {
		return false
	}
	for k := range a.Parts {
		if !a.Parts[k].Equals(b.Parts[k]) {
			return false
		}
	}
	return true
}
