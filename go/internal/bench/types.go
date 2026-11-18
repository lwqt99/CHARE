// Package bench executes the real in-memory protocol workload. Qualification
// labels are synthetic test-oracle inputs, never provided to public aggregation.
package bench

import "example.org/chare/internal/nativegroup"

// This is shared native-environment work before either scheme's protocol
// Setup. It is recorded separately from per-scheme measurement intervals.
type NativeContextEvidence struct {
	DurationNS int64               `json:"duration_ns"`
	Status     string              `json:"status"`
	Admission  *nativegroup.Report `json:"admission,omitempty"`
	Error      string              `json:"error,omitempty"`
}

type Config struct {
	Capacity          int  `json:"capacity"`
	Attributes        int  `json:"attributes"`
	Replicate         int  `json:"replicate"`
	Revocations       int  `json:"revocations"`
	Acquisitions      int  `json:"acquisitions"`
	ColdAuditAllUsers bool `json:"cold_audit_all_users"`
	PaperStudy        bool `json:"paper_study,omitempty"`
}

type Measurement struct {
	Scheme     string `json:"scheme"`
	Operation  string `json:"operation"`
	Mode       string `json:"mode"`
	DurationNS int64  `json:"duration_ns"`
	Bytes      int64  `json:"bytes"`
	SourceOps  int64  `json:"source_ops"`
	Pairings   int64  `json:"pairings"`
	Count      int    `json:"count"`
	Detail     string `json:"detail"`
}

type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type Result struct {
	NativeContext *NativeContextEvidence `json:"native_context,omitempty"`
	Measurements  []Measurement          `json:"measurements"`
	Checks        []Check                `json:"checks"`
	Workload      *WorkloadEvidence      `json:"workload_evidence,omitempty"`
	ColdAudit     *ColdAuditEvidence     `json:"cold_audit_evidence,omitempty"`
	Study         *StudyEvidence         `json:"study_evidence,omitempty"`
}
