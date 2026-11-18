package bench

import "fmt"

const WorkloadSchedule = "synthetic-active-only-slot-major-v1"

// This is the benchmark's synthetic input distribution, never a directory
// qualification oracle. Preserve the existing 64-column fixture convention.
func syntheticQualification(slot, attribute int) bool {
	return ((uint64(slot) >> uint(attribute%63)) & 1) == 1
}

// ActiveQualificationCount describes the chosen synthetic fixture, not a
// private directory query. Planning is outside both protocols' measured work.
func ActiveQualificationCount(capacity, attributes int) int {
	count := 0
	for slot := 0; slot < capacity; slot++ {
		for a := 0; a < attributes; a++ {
			if syntheticQualification(slot, a) {
				count++
			}
		}
	}
	return count
}

type revocationSelection struct{ attribute, slot int }

func activeRevocationPlan(capacity, attributes, requested int) ([]revocationSelection, error) {
	available := ActiveQualificationCount(capacity, attributes)
	if requested < 0 || requested > available {
		return nil, fmt.Errorf("requested %d effective revocations, but synthetic N=%d m=%d has only %d active qualifications; no implicit regrant or redundant denial", requested, capacity, attributes, available)
	}
	plan := make([]revocationSelection, 0, requested)
	for slot := 0; slot < capacity && len(plan) < requested; slot++ {
		for a := 0; a < attributes && len(plan) < requested; a++ {
			if syntheticQualification(slot, a) {
				plan = append(plan, revocationSelection{a, slot})
			}
		}
	}
	return plan, nil
}

// Diagnostic evidence belongs only to the synthetic benchmark result. It is
// not a public protocol message or an extra qualification-disclosure API.
type RevocationEvent struct {
	Step              int    `json:"step"`
	Attribute         int    `json:"attribute"`
	Slot              int    `json:"slot"`
	Before            bool   `json:"before"`
	After             bool   `json:"after"`
	PreviousVersion   uint64 `json:"previous_version"`
	InstalledVersion  uint64 `json:"installed_version"`
	Sequence          uint64 `json:"sequence"`
	CHAREInstalled    bool   `json:"chare_installed"`
	BaselinePublished bool   `json:"baseline_published"`
}

type WorkloadEvidence struct {
	Schedule                      string            `json:"schedule"`
	InitialActiveQualifications   int               `json:"initial_active_qualifications"`
	RequestedRevocations          int               `json:"requested_revocations"`
	CompletedEffectiveRevocations int               `json:"completed_effective_revocations"`
	RequestedAcquisitions         int               `json:"requested_acquisitions"`
	CompletedAcquisitions         int               `json:"completed_acquisitions"`
	Events                        []RevocationEvent `json:"events"`
}

// ValidateWorkloadEvidence is a completion gate, not a cryptographic proof.
// Failed runs retain their incomplete events; only completed runs may pass.
func ValidateWorkloadEvidence(cfg Config, e *WorkloadEvidence) error {
	if e == nil || e.Schedule != WorkloadSchedule ||
		e.InitialActiveQualifications != ActiveQualificationCount(cfg.Capacity, cfg.Attributes) ||
		e.RequestedRevocations != cfg.Revocations || e.RequestedAcquisitions != cfg.Acquisitions ||
		e.CompletedEffectiveRevocations != cfg.Revocations || e.CompletedAcquisitions != cfg.Acquisitions ||
		len(e.Events) != cfg.Revocations {
		return fmt.Errorf("incomplete or inconsistent effective-revocation workload evidence")
	}
	seen := make(map[revocationSelection]bool, len(e.Events))
	plan, err := activeRevocationPlan(cfg.Capacity, cfg.Attributes, cfg.Revocations)
	if err != nil {
		return err
	}
	for i, event := range e.Events {
		key := revocationSelection{event.Attribute, event.Slot}
		if event.Step != i+1 || key != plan[i] || event.Attribute < 0 || event.Attribute >= cfg.Attributes ||
			event.Slot < 0 || event.Slot >= cfg.Capacity || seen[key] ||
			!syntheticQualification(event.Slot, event.Attribute) || !event.Before || event.After ||
			!event.CHAREInstalled || !event.BaselinePublished || event.PreviousVersion != 1 ||
			event.InstalledVersion != 2 || event.Sequence != uint64(i+1) {
			return fmt.Errorf("invalid effective-revocation event %d", i+1)
		}
		seen[key] = true
	}
	return nil
}
