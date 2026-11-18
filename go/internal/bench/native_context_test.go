package bench

import (
	"github.com/Nik-U/pbc"
	"testing"
)

func TestNativeContextCostsAndFailuresAreRecorded(t *testing.T) {
	cfg := Config{Capacity: 4, Attributes: 2, Revocations: 1, Acquisitions: 1}
	result, err := RunCase(pbc.GenerateA(64, 256).String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := result.NativeContext
	if e == nil || e.Status != "passed" || e.DurationNS < 0 || e.Admission == nil || e.Admission.Initializations < 1 || e.Admission.SourceProbes < 1 {
		t.Fatalf("missing native work: %+v", e)
	}
	failed, err := RunCase("not trusted native parameters", cfg)
	if err == nil || failed.NativeContext == nil || failed.NativeContext.Status != "failed" || failed.NativeContext.Error == "" || failed.NativeContext.Admission != nil {
		t.Fatal("native failure not distinguished from a zero-cost success")
	}
}
