package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"example.org/chare/internal/bench"
)

const ConfigSchema = "chare-run-config-v1"

type Options struct {
	ConfigPath     string
	ParametersPath string
	OutputRoot     string
}

type CurveConfig struct {
	Type           string `json:"type"`
	RBits          uint32 `json:"r_bits"`
	QBits          uint32 `json:"q_bits"`
	ParametersFile string `json:"parameters_file,omitempty"`
}

type Workload struct {
	Revocations               int  `json:"revocations"`
	Acquisitions              int  `json:"acquisitions"`
	RevocationsEqualCapacity  bool `json:"revocations_equal_capacity"`
	AcquisitionsEqualCapacity bool `json:"acquisitions_equal_capacity"`
	ColdAuditAllUsers         bool `json:"cold_audit_all_users"`
}

type Configuration struct {
	Schema          string      `json:"schema"`
	Label           string      `json:"label"`
	Curve           CurveConfig `json:"curve"`
	Capacities      []int       `json:"capacities"`
	Attributes      []int       `json:"attributes"`
	Replicates      int         `json:"replicates"`
	Workload        Workload    `json:"workload"`
	ContinueOnError bool        `json:"continue_on_error"`
	PaperStudy      bool        `json:"paper_study,omitempty"`
}

func DefaultConfiguration() Configuration {
	return Configuration{
		Schema: ConfigSchema, Label: "sanity",
		Curve:      CurveConfig{Type: "a", RBits: 160, QBits: 512},
		Capacities: []int{4, 8}, Attributes: []int{2}, Replicates: 1,
		Workload: Workload{Revocations: 2, Acquisitions: 2}, ContinueOnError: true,
	}
}

func loadConfiguration(path string) (Configuration, error) {
	if path == "" {
		return DefaultConfiguration(), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return Configuration{}, err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	dec.DisallowUnknownFields()
	var cfg Configuration
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("configuration: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return cfg, errors.New("configuration must contain exactly one JSON object")
	}
	if cfg.Curve.ParametersFile != "" && !filepath.IsAbs(cfg.Curve.ParametersFile) {
		cfg.Curve.ParametersFile = filepath.Join(filepath.Dir(path), cfg.Curve.ParametersFile)
	}
	return cfg, nil
}

func (cfg Configuration) validate() error {
	if cfg.Schema != ConfigSchema {
		return fmt.Errorf("unsupported configuration schema %q", cfg.Schema)
	}
	if cfg.Label == "" || len(cfg.Label) > 80 {
		return errors.New("label must have 1--80 bytes")
	}
	if cfg.Curve.Type != "a" {
		return errors.New("this mainline requires a symmetric Type-A pairing")
	}
	if cfg.Curve.ParametersFile == "" && (cfg.Curve.RBits < 16 || cfg.Curve.QBits <= cfg.Curve.RBits || cfg.Curve.QBits > 16384) {
		return errors.New("generated parameter profile requires 16 <= r_bits < q_bits <= 16384; these are size bounds, not security-strength certification")
	}
	if cfg.Replicates < 1 || cfg.Replicates > 100000 {
		return errors.New("replicates must be between 1 and 100000")
	}
	if len(cfg.Capacities) == 0 || len(cfg.Attributes) == 0 {
		return errors.New("capacity and attribute grids must be nonempty")
	}
	seen := make(map[int]bool)
	for _, n := range cfg.Capacities {
		if n < 2 || n > 1000000 || seen[n] {
			return errors.New("capacities must be unique integers in [2,1000000]")
		}
		seen[n] = true
		if cfg.PaperStudy && n < 4 {
			return errors.New("paper_study requires capacity at least four")
		}
	}
	seen = make(map[int]bool)
	for _, m := range cfg.Attributes {
		if m < 1 || m > 64 || seen[m] {
			return errors.New("attribute dimensions must be unique integers in [1,64]")
		}
		seen[m] = true
	}
	if cfg.Workload.Revocations < 0 || cfg.Workload.Acquisitions < 0 {
		return errors.New("workload counts cannot be negative")
	}
	if cfg.Workload.RevocationsEqualCapacity && cfg.Workload.Revocations != 0 || cfg.Workload.AcquisitionsEqualCapacity && cfg.Workload.Acquisitions != 0 {
		return errors.New("use either an explicit workload count or equal_capacity, not both")
	}
	for _, n := range cfg.Capacities {
		requested := cfg.Workload.Revocations
		if cfg.Workload.RevocationsEqualCapacity {
			requested = n
		}
		for _, m := range cfg.Attributes {
			available := bench.ActiveQualificationCount(n, m)
			if requested > available {
				return fmt.Errorf("N=%d m=%d requests %d effective revocations, but has only %d active synthetic qualifications", n, m, requested, available)
			}
		}
	}
	if uint64(len(cfg.Capacities))*uint64(len(cfg.Attributes))*uint64(cfg.Replicates) > 1000000 {
		return errors.New("grid exceeds one million cases")
	}
	return nil
}
