package runner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"example.org/chare/internal/bench"
	"example.org/chare/internal/projectpath"
)

type Summary struct {
	Directory               string
	Archive                 string
	Passed, Failed, Skipped int
}

type caseStatus struct {
	CaseID        string       `json:"case_id"`
	Configuration bench.Config `json:"configuration"`
	Status        string       `json:"status"`
	StartedUTC    string       `json:"started_utc,omitempty"`
	FinishedUTC   string       `json:"finished_utc,omitempty"`
	Checks        int          `json:"checks"`
	Error         string       `json:"error,omitempty"`
}

func Run(ctx context.Context, options Options) (summary Summary, runErr error) {
	cfg, err := loadConfiguration(options.ConfigPath)
	if err != nil {
		return summary, err
	}
	if options.ParametersPath != "" {
		cfg.Curve.ParametersFile = options.ParametersPath
	}
	if err = cfg.validate(); err != nil {
		return summary, err
	}
	outputRoot, err := projectpath.OutputRoot(options.OutputRoot)
	if err != nil {
		return summary, err
	}
	runID, err := newRunID(cfg.Label)
	if err != nil {
		return summary, err
	}
	dir := filepath.Join(outputRoot, runID)
	if err = os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return summary, err
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		return summary, err
	}
	summary.Directory = dir
	manifest := map[string]any{"schema": "chare-run-manifest-v1", "implementation_version": "chare-go-pbc-v0.7.0", "protocol_version": bench.ProtocolVersion, "workload_schedule": bench.WorkloadSchedule, "protocol_profile": "symmetric-rational-source-conditional-history", "transport_profile": "optional exact-byte prefix cache measured alongside full wire; same original KDF; all-client entry installs and one-client packet expansion", "run_id": runID, "started_utc": time.Now().UTC().Format(time.RFC3339Nano), "status": "preparing", "configuration": cfg, "environment": environment(), "measurement_scope": "actual PBC operations; no security proof inferred from functional checks or timings", "functional_validation": "implementation consistency checks only; not a security experiment", "baseline_scope": "source-DH has independent reception keys, certificates, explicit-list authorization epochs, first acquisition and history; externally supplied public lists; not hidden-qualification functional equivalence"}
	if cfg.PaperStudy {
		manifest["paper_study_profile"] = "chare-native-study-v1; paired helper/directory paths; tree/cycle actual source-group service; component branches separate from lifecycle"
	}
	manifest["receiver_refresh_profile"] = "signed-state-binding-and-atomic-local-open-v1"
	var accepted []sample
	defer func() {
		if e := writeSummary(filepath.Join(dir, "summary.csv"), accepted); e != nil {
			runErr = errors.Join(runErr, e)
		}
		if e := writeFinalState(dir, manifest, summary, runErr, ""); e != nil {
			runErr = errors.Join(runErr, e)
			// Best effort after a finalization error: a successful rewrite must
			// not preserve an earlier optimistic completed status.
			runErr = errors.Join(runErr, writeFinalState(dir, manifest, summary, runErr, "finalization_failed"))
		}
		archive, e := packageResults(dir)
		if e != nil {
			runErr = errors.Join(runErr, fmt.Errorf("packaging failed: %w", e))
			// Preserve a partial archive under an explicitly nonfinal name.
			zipPath := filepath.Join(dir, "return.zip")
			if _, statErr := os.Stat(zipPath); statErr == nil {
				runErr = errors.Join(runErr, os.Rename(zipPath, zipPath+".partial"))
			}
			for _, name := range []string{"return.zip.sha256", "SHA256SUMS"} {
				if removeErr := os.Remove(filepath.Join(dir, name)); removeErr != nil && !os.IsNotExist(removeErr) {
					runErr = errors.Join(runErr, removeErr)
				}
			}
			runErr = errors.Join(runErr, writeFinalState(dir, manifest, summary, runErr, "packaging_failed"))
		} else {
			summary.Archive = archive
		}
	}()
	sourceInfo := sourceSnapshot()
	manifest["source_snapshot_status"] = sourceInfo.Status
	if err = writeJSON(filepath.Join(dir, "source_manifest.json"), sourceInfo); err != nil {
		return summary, err
	}
	if err = writeJSON(filepath.Join(dir, "config.json"), cfg); err != nil {
		return summary, err
	}
	if err = writeJSON(filepath.Join(dir, "manifest.json"), manifest); err != nil {
		return summary, err
	}
	fmt.Printf("Run %s\nPreparing or importing public Type-A parameters; no concrete security-bit claim.\n", runID)
	params, parameterInfo, err := prepareParameters(cfg)
	if err != nil {
		return summary, err
	}
	manifest["parameters"] = parameterInfo
	if err = os.WriteFile(filepath.Join(dir, "parameters.txt"), []byte(params), 0600); err != nil {
		return summary, err
	}
	if err = writeJSON(filepath.Join(dir, "manifest.json"), manifest); err != nil {
		return summary, err
	}
	rawFile, raw, err := newCSV(filepath.Join(dir, "raw.csv"), []string{"run_id", "case_id", "capacity", "attributes", "replicate", "revocations", "acquisitions", "scheme", "operation", "mode", "duration_ns", "bytes", "source_ops", "pairings", "count", "detail"})
	if err != nil {
		return summary, err
	}
	defer rawFile.Close()
	checkFile, checks, err := newCSV(filepath.Join(dir, "checks.csv"), []string{"case_id", "name", "passed", "detail"})
	if err != nil {
		return summary, err
	}
	defer checkFile.Close()
	cases := grid(cfg)
	manifest["planned_cases"] = len(cases)
	stopReason := ""
	for index, c := range cases {
		id := fmt.Sprintf("case_%05d_n%d_m%d_r%d", index+1, c.Capacity, c.Attributes, c.Replicate)
		caseDir := filepath.Join(dir, "cases", id)
		if err = os.MkdirAll(caseDir, 0700); err != nil {
			return summary, err
		}
		state := caseStatus{CaseID: id, Configuration: c, Status: "pending"}
		if ctx.Err() != nil {
			stopReason = "interrupted before starting this case"
		}
		if stopReason != "" {
			state.Status = "skipped"
			state.Error = stopReason
			summary.Skipped++
			if err = writeJSON(filepath.Join(caseDir, "status.json"), state); err != nil {
				return summary, err
			}
			continue
		}
		state.Status = "running"
		state.StartedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		caseStarted := time.Now()
		if err = writeJSON(filepath.Join(caseDir, "status.json"), state); err != nil {
			return summary, err
		}
		fmt.Printf("[%d/%d] capacity=%d attributes=%d replicate=%d\n", index+1, len(cases), c.Capacity, c.Attributes, c.Replicate)
		result, caseErr := runCaseSafely(params, c)
		if caseErr == nil {
			caseErr = bench.ValidateWorkloadEvidence(c, result.Workload)
		}
		if caseErr == nil {
			caseErr = bench.ValidateStudyEvidence(c, result.Study)
		}
		state.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		state.Checks = len(result.Checks)
		if len(result.Checks) == 0 {
			caseErr = errors.Join(caseErr, errors.New("no functional checks returned; case is not eligible for summary"))
		}
		for _, check := range result.Checks {
			if e := checks.Write([]string{id, check.Name, fmt.Sprint(check.Passed), check.Detail}); e != nil {
				return summary, e
			}
			if !check.Passed {
				caseErr = errors.Join(caseErr, fmt.Errorf("check failed: %s: %s", check.Name, check.Detail))
			}
		}
		caseRows := make([]sample, 0, len(result.Measurements))
		for _, measurement := range result.Measurements {
			row := sample{CaseID: id, Config: c, Value: measurement}
			caseRows = append(caseRows, row)
			if e := raw.Write(measurementRow(runID, row)); e != nil {
				return summary, e
			}
			if measurement.DurationNS < 0 || measurement.Bytes < 0 || measurement.SourceOps < 0 || measurement.Pairings < 0 || measurement.Count < 0 {
				caseErr = errors.Join(caseErr, errors.New("measurement contains a negative numeric field"))
			}
		}
		if err = flushCSV(rawFile, raw); err != nil {
			return summary, err
		}
		if err = flushCSV(checkFile, checks); err != nil {
			return summary, err
		}
		if err = writeJSON(filepath.Join(caseDir, "result.json"), result); err != nil {
			return summary, err
		}
		if err = writeJSON(filepath.Join(caseDir, "checks.json"), result.Checks); err != nil {
			return summary, err
		}
		if caseErr != nil {
			state.Status = "failed"
			state.Error = caseErr.Error()
			summary.Failed++
			fmt.Fprintf(os.Stderr, "%s failed: %v\n", id, caseErr)
			if !cfg.ContinueOnError {
				stopReason = "previous case failed and continue_on_error is false"
			}
		} else {
			state.Status = "passed"
			summary.Passed++
			accepted = append(accepted, caseRows...)
		}
		if err = writeJSON(filepath.Join(caseDir, "status.json"), state); err != nil {
			return summary, err
		}
		fmt.Printf("[%d/%d] %s: %s in %s; completed-case files saved\n", index+1, len(cases), id, state.Status, time.Since(caseStarted).Round(time.Millisecond))
	}
	if summary.Failed > 0 || summary.Skipped > 0 {
		return summary, fmt.Errorf("%d failed and %d skipped cases; raw results and failures were retained", summary.Failed, summary.Skipped)
	}
	return summary, nil
}

func grid(cfg Configuration) []bench.Config {
	var result []bench.Config
	for _, n := range cfg.Capacities {
		for _, m := range cfg.Attributes {
			for rep := 1; rep <= cfg.Replicates; rep++ {
				r, a := cfg.Workload.Revocations, cfg.Workload.Acquisitions
				if cfg.Workload.RevocationsEqualCapacity {
					r = n
				}
				if cfg.Workload.AcquisitionsEqualCapacity {
					a = n
				}
				result = append(result, bench.Config{Capacity: n, Attributes: m, Replicate: rep, Revocations: r, Acquisitions: a, ColdAuditAllUsers: cfg.Workload.ColdAuditAllUsers, PaperStudy: cfg.PaperStudy})
			}
		}
	}
	return result
}

func runCaseSafely(params string, cfg bench.Config) (result bench.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("RunCase panic: %v", r)
		}
	}()
	return bench.RunCase(params, cfg)
}

func newRunID(label string) (string, error) {
	var safe strings.Builder
	for _, r := range label {
		if r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_') {
			safe.WriteRune(r)
		} else {
			safe.WriteByte('_')
		}
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405.000000000Z") + "_" + safe.String() + "_" + hex.EncodeToString(suffix), nil
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func writeFinalState(dir string, manifest map[string]any, summary Summary, prior error, forced string) error {
	status := "completed"
	if prior != nil {
		status = "incomplete_or_failed"
	}
	if forced != "" {
		status = forced
	}
	manifest["status"] = status
	manifest["finished_utc"] = time.Now().UTC().Format(time.RFC3339Nano)
	manifest["passed_cases"], manifest["failed_cases"], manifest["skipped_cases"] = summary.Passed, summary.Failed, summary.Skipped
	manifest["error"] = errorText(prior)
	manifestErr := writeJSON(filepath.Join(dir, "manifest.json"), manifest)
	if manifestErr != nil {
		status = "finalization_failed"
	}
	statusErr := writeJSON(filepath.Join(dir, "status.json"), map[string]any{"status": status, "passed": summary.Passed, "failed": summary.Failed, "skipped": summary.Skipped, "error": errorText(errors.Join(prior, manifestErr))})
	return errors.Join(manifestErr, statusErr)
}
