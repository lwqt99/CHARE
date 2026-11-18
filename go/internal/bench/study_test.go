package bench

import (
	"github.com/Nik-U/pbc"
	"testing"
)

func TestNativePaperStudyPairedPathsAndRecovery(t *testing.T) {
	params := pbc.GenerateA(64, 256).String() // Functional tests only; not paper timing data.
	for _, rep := range []int{1, 2} {
		cfg := Config{Capacity: 4, Attributes: 2, Replicate: rep, Revocations: 4, Acquisitions: 4, PaperStudy: true}
		result, err := RunCase(params, cfg)
		if err != nil {
			t.Fatal(rep, err)
		}
		if err = ValidateStudyEvidence(cfg, result.Study); err != nil {
			t.Fatal(err)
		}
		for _, check := range result.Checks {
			if !check.Passed {
				t.Fatal(check.Name)
			}
		}
		want := "rebuild"
		if rep == 2 {
			want = "delta"
		}
		if result.Study.ComparisonOrder[0] != want {
			t.Fatal("paired execution order")
		}
		if ValidateStudyEvidence(cfg, nil) == nil {
			t.Fatal("missing study accepted")
		}
		result.Study.Services[0].RecoveryKeyEqual = false
		if ValidateStudyEvidence(cfg, result.Study) == nil {
			t.Fatal("failed recovery accepted")
		}
	}
}
