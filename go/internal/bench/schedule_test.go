package bench

import (
	"strings"
	"testing"

	"github.com/Nik-U/pbc"
)

func TestActivePlanFourClassesAndAvailability(t *testing.T) {
	want := []revocationSelection{{0, 1}, {1, 2}, {0, 3}, {1, 3}}
	got, err := activeRevocationPlan(4, 2, 4)
	if err != nil || len(got) != len(want) {
		t.Fatal("four-class schedule", got, err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatal("not a distinct active qualification", i, got[i])
		}
	}
	for _, n := range []int{4, 8, 16, 32, 64, 128, 256} {
		if ActiveQualificationCount(n, 2) != n {
			t.Fatal("paper workload does not contain N initially active qualifications", n)
		}
	}
	if _, err := activeRevocationPlan(4, 2, 5); err == nil {
		t.Fatal("request silently includes a redundant denial or implicit regrant")
	}
	if _, err := activeRevocationPlan(4, 1, 4); err == nil {
		t.Fatal("one-attribute fixture has only two active qualifications")
	}
	if got, err := activeRevocationPlan(4, 2, 0); err != nil || len(got) != 0 {
		t.Fatal("zero-update workload", err)
	}
}

func TestWorkloadEvidenceRejectsMissingAndNoopEvents(t *testing.T) {
	cfg := Config{Capacity: 4, Attributes: 2, Revocations: 2, Acquisitions: 2}
	base := WorkloadEvidence{
		Schedule: WorkloadSchedule, InitialActiveQualifications: 4,
		RequestedRevocations: 2, CompletedEffectiveRevocations: 2,
		RequestedAcquisitions: 2, CompletedAcquisitions: 2,
		Events: []RevocationEvent{
			{Step: 1, Attribute: 0, Slot: 1, Before: true, PreviousVersion: 1, InstalledVersion: 2, Sequence: 1, CHAREInstalled: true, BaselinePublished: true},
			{Step: 2, Attribute: 1, Slot: 2, Before: true, PreviousVersion: 1, InstalledVersion: 2, Sequence: 2, CHAREInstalled: true, BaselinePublished: true},
		},
	}
	if err := ValidateWorkloadEvidence(cfg, &base); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*WorkloadEvidence){
		func(e *WorkloadEvidence) { e.Events[0].Before = false },
		func(e *WorkloadEvidence) { e.Events[0].After = true },
		func(e *WorkloadEvidence) { e.Events[1].Slot, e.Events[1].Attribute = 1, 0 },
		func(e *WorkloadEvidence) { e.Events[0].BaselinePublished = false },
		func(e *WorkloadEvidence) { e.Events[0].CHAREInstalled = false },
		func(e *WorkloadEvidence) { e.Events[0].InstalledVersion = 1 },
		func(e *WorkloadEvidence) { e.Events[0].Sequence = 0 },
		func(e *WorkloadEvidence) { e.CompletedAcquisitions-- },
		func(e *WorkloadEvidence) { e.Events = e.Events[:1] },
		func(e *WorkloadEvidence) { e.Events[0].Slot = 3 },
	}
	for i, mutate := range mutations {
		e := base
		e.Events = append([]RevocationEvent(nil), base.Events...)
		mutate(&e)
		if ValidateWorkloadEvidence(cfg, &e) == nil {
			t.Fatal("invalid evidence accepted", i)
		}
	}
	if ValidateWorkloadEvidence(cfg, nil) == nil {
		t.Fatal("missing evidence accepted")
	}
}

func TestActualEffectiveRevocationLifecycle(t *testing.T) {
	// Native functional parameters, not a claimed cryptographic security level.
	params := pbc.GenerateA(64, 256).String()
	for _, r := range []int{3, 4} {
		cfg := Config{Capacity: 4, Attributes: 2, Replicate: 1, Revocations: r, Acquisitions: r}
		result, err := RunCase(params, cfg)
		if err != nil {
			t.Fatalf("%d actual withdrawals: %v", r, err)
		}
		if err = ValidateWorkloadEvidence(cfg, result.Workload); err != nil {
			t.Fatal(err)
		}
		foundB, foundOld, foundDHOId := false, false, false
		for _, c := range result.Checks {
			if !c.Passed {
				t.Fatal(c.Name)
			}
			foundB = foundB || c.Name == "after_updates_B/slot3"
			foundOld = foundOld || strings.HasPrefix(c.Name, "retained_old_")
			foundDHOId = foundDHOId || c.Name == "DH_retained_old_state"
		}
		if !foundB || !foundDHOId || !foundOld {
			t.Fatal("actual partial-revocation/old-state path not exercised", foundB, foundDHOId, foundOld)
		}
	}
	result, err := RunCase("invalid params must not be parsed", Config{Capacity: 4, Attributes: 1, Revocations: 4})
	if err == nil || !strings.Contains(err.Error(), "only 2 active") || len(result.Measurements) != 0 {
		t.Fatal("unfulfillable workload must fail before native setup", err)
	}
}
