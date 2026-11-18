package core

import (
	"math/big"
	"strings"
	"testing"

	"github.com/Nik-U/pbc"
)

// Exercise the actual C parameter printer used by the batch runner. On
// Windows the vendored wrapper uses a temporary-file memstream fallback.
// This is a portability regression test, not a security/benchmark fixture.
func TestNativeParameterSerializationRoundTrip(t *testing.T) {
	params, err := pbc.NewParamsFromString(functionalParams)
	if err != nil {
		t.Fatal(err)
	}
	printed := params.String()
	if !strings.HasPrefix(printed, "type a\n") || !strings.Contains(printed, "r 641\n") {
		t.Fatalf("parameter printer returned incomplete text: %q", printed)
	}
	ctx, err := NewContext(printed)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.P.Int64() != 641 || !ctx.Pairing.IsSymmetric() {
		t.Fatal("native parameter serialization changed the group")
	}
	copy, err := pbc.NewParamsFromString(printed)
	if err != nil || copy.String() != printed {
		t.Fatal("native parameter text did not round trip exactly")
	}
}

// Actual 160/512 Type-A output, saved from the first native batch. The small
// 641-order fixture uses a different PBC field backend and cannot detect a
// broken multi-limb Montgomery implementation. This is a functional fixture,
// not a security-strength claim or benchmark measurement.
const largeFunctionalParams = "type a\nq 2427729459290566819246490761156778114370188540020874924693220539171758510991010176766236127624710719569066330297638449059348908506616607197233884893788667\nh 3322239807714833774864731304333181121177359365946275913120346567833295529536003460366379657116911638395388\nr 730750818665451459101842416358141509827966402561\nexp2 159\nexp1 17\nsign1 1\nsign0 1\n"

func TestNativeLargeFieldBilinearity(t *testing.T) {
	ctx, err := NewContext(largeFunctionalParams)
	if err != nil {
		t.Fatal(err)
	}
	pp, err := Setup(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	a := new(big.Int).Sub(ctx.P, big.NewInt(19))
	b := new(big.Int).Rsh(new(big.Int).Set(ctx.P), 2)
	left := ctx.Pair(ctx.SourceScale(pp.G, a), ctx.SourceScale(pp.H, b))
	right := ctx.TargetScale(ctx.Pair(pp.G, pp.H), ctx.mul(a, b))
	if !left.Equals(right) {
		t.Fatal("native large-field bilinearity failed; inspect actual PBC/GMP build")
	}
	root, _, err := UserKeyGen(pp, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateRoot(pp, root); err != nil {
		t.Fatalf("large-field generated root failed public equations: %v", err)
	}
}
