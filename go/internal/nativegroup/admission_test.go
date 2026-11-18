package nativegroup

import (
	"crypto/rand"
	"github.com/Nik-U/pbc"
	"math/big"
	"testing"
)

const smallParams = "type a\nq 4025338979\nh 6279780\nr 641\nexp2 9\nexp1 7\nsign1 1\nsign0 1\n"

// Native curve initialization chooses x=0, yielding the two-torsion point
// (0,0), whose even cofactor multiple is zero. Other random calls are genuine.
// This provider is used ONLY to reproduce the actual native failure in tests.
type zeroCoordinate struct{ used bool }

func (s *zeroCoordinate) Rand(limit *big.Int) *big.Int {
	if !s.used && limit.Cmp(big.NewInt(4025338979)) == 0 {
		s.used = true
		return big.NewInt(0)
	}
	x, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(err)
	}
	return x
}
func badPairing(t *testing.T) *pbc.Pairing {
	t.Helper()
	pbc.SetRandomProvider(&zeroCoordinate{})
	defer pbc.SetCryptoRandom()
	p, err := pbc.NewPairingFromString(smallParams)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestNativeZeroCachedBaseIsPersistent(t *testing.T) {
	p := badPairing(t)
	for i := 0; i < 1024; i++ {
		if !p.NewG1().Rand().Is0() {
			t.Fatal("native failure reproduction did not hold")
		}
	}
}
func TestAdmissionRejectsBadInstanceBeforeProtocolSetup(t *testing.T) {
	calls := 0
	p, report, err := admit(func() (*pbc.Pairing, error) {
		calls++
		if calls == 1 {
			return badPairing(t), nil
		}
		pbc.SetCryptoRandom()
		return pbc.NewPairingFromString(smallParams)
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if report.RejectedInstances < 1 || report.Initializations < 2 || report.Initializations != calls || report.SourceProbes < ProbesPerSource+1 {
		t.Fatalf("missing actual admission accounting: %+v", report)
	}
	seen := false
	for i := 0; i < ProbesPerSource; i++ {
		if !p.NewG1().Rand().Is0() {
			seen = true
			break
		}
	}
	if !seen {
		t.Fatal("admitted unusable native base")
	}
}
func TestAdmissionExhaustionIsExplicit(t *testing.T) {
	p := badPairing(t)
	got, report, err := admit(func() (*pbc.Pairing, error) { return p, nil }, true)
	if err == nil || got != nil || report.Initializations != MaxInitializations || report.RejectedInstances != MaxInitializations || report.SourceProbes != MaxInitializations*ProbesPerSource {
		t.Fatalf("not bounded explicit failure: %+v %v", report, err)
	}
}
