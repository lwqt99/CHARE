package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const importFixture = "type a\nq 4025338979\nh 6279780\nr 641\nexp2 9\nexp1 7\nsign1 1\nsign0 1\n"

func TestImportedParameterAdmission(t *testing.T) {
	path := filepath.Join(t.TempDir(), "public.params")
	cfg := DefaultConfiguration()
	cfg.Curve.ParametersFile = path
	if err := os.WriteFile(path, []byte(importFixture), 0600); err != nil {
		t.Fatal(err)
	}
	text, info, err := prepareParameters(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if text != importFixture || info.RBitsActual != 10 || info.QBitsActual != 32 || !info.Admission.BeforeNative || info.Admission.SecurityCertified {
		t.Fatal("incorrect admission metadata")
	}
	if err := os.WriteFile(path, []byte(strings.Replace(importFixture, "exp1 7", "exp1 6", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareParameters(cfg); err == nil {
		t.Fatal("admitted inconsistent Miller-loop exponent")
	}
	cfg.Capacities = []int{640}
	if err := os.WriteFile(path, []byte(importFixture), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareParameters(cfg); err == nil {
		t.Fatal("admitted capacity p-1")
	}
}
