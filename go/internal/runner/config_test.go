package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPaperStudyPropagationAndMinimumCapacity(t *testing.T) {
	cfg := DefaultConfiguration()
	cfg.PaperStudy = true
	for _, c := range grid(cfg) {
		if !c.PaperStudy {
			t.Fatal("missing study flag")
		}
	}
	cfg.Capacities = []int{2}
	cfg.Workload.Revocations = 0
	if cfg.validate() == nil {
		t.Fatal("invalid study dimension accepted")
	}
}

func TestConfigurationRejectsAmbiguousWorkload(t *testing.T) {
	cfg := DefaultConfiguration()
	cfg.Workload.RevocationsEqualCapacity = true
	if cfg.validate() == nil {
		t.Fatal("explicit and capacity-dependent revocation counts must not both be accepted")
	}
	cfg.Workload.Revocations = 0
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationRejectsDuplicateGrid(t *testing.T) {
	cfg := DefaultConfiguration()
	cfg.Capacities = []int{4, 4}
	if cfg.validate() == nil {
		t.Fatal("duplicate capacities would silently duplicate samples")
	}
}

func TestConfigurationRequiresEffectiveRevocations(t *testing.T) {
	cfg := DefaultConfiguration()
	cfg.Workload.Revocations, cfg.Workload.RevocationsEqualCapacity = 0, true
	cfg.Attributes = []int{1}
	if cfg.validate() == nil {
		t.Fatal("N withdrawals cannot be made from N/2 active fixture qualifications")
	}
	cfg.Attributes = []int{2}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationMatchesAttributeLimit(t *testing.T) {
	cfg := DefaultConfiguration()
	cfg.Attributes = []int{64}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Attributes = []int{65}
	if cfg.validate() == nil {
		t.Fatal("attribute count beyond the protocol's implemented limit accepted")
	}
}

func TestConfigurationRejectsUnknownAndTrailingFields(t *testing.T) {
	for _, data := range []string{`{"schema":"chare-run-config-v1","replicatez":4}`, `{} {}`} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfiguration(path); err == nil {
			t.Fatal("ambiguous input accepted")
		}
	}
}

func TestParameterPathResolvesAgainstConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(path, []byte(`{"curve":{"parameters_file":"public.params"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfiguration(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Curve.ParametersFile != filepath.Join(dir, "public.params") {
		t.Fatal("parameter path must be config-relative")
	}
}

func TestColdAuditScopePropagatesToEveryCase(t *testing.T) {
	cfg := DefaultConfiguration()
	cfg.Workload.ColdAuditAllUsers = true
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	for _, item := range grid(cfg) {
		if !item.ColdAuditAllUsers {
			t.Fatal("full-cohort workload silently narrowed")
		}
	}
	cfg.Workload.ColdAuditAllUsers = false
	for _, item := range grid(cfg) {
		if item.ColdAuditAllUsers {
			t.Fatal("explicit one-client profile silently expanded")
		}
	}
}
