package core

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/Nik-U/pbc"
)

// Small parameters from the upstream PBC wrapper's functional-test fixture.
// These are NOT benchmark parameters or a concrete-security recommendation.
const functionalParams = "type a\nq 4025338979\nh 6279780\nr 641\nexp2 9\nexp1 7\nsign1 1\nsign0 1\n"

type fixture struct {
	pp     *Params
	roots  []*Root
	users  []*UserSecret
	rows   [][]*Row
	deltas [][]*big.Int
	agg    *Prepared
}

func newFixture(t *testing.T, n int) *fixture {
	t.Helper()
	c, err := NewContext(functionalParams)
	if err != nil {
		t.Fatal(err)
	}
	pp, err := Setup(c, n)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{pp: pp, roots: make([]*Root, n), users: make([]*UserSecret, n), rows: make([][]*Row, 2), deltas: make([][]*big.Int, 2)}
	for i := 0; i < n; i++ {
		f.roots[i], f.users[i], err = UserKeyGen(pp, i)
		if err != nil {
			t.Fatal(err)
		}
	}
	for b := 0; b < 2; b++ {
		f.rows[b] = make([]*Row, n)
		f.deltas[b] = make([]*big.Int, n)
		for i := 0; i < n; i++ {
			f.rows[b][i], f.deltas[b][i], err = Issue(pp, f.roots[i], (i>>b)&1 == 1)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	f.agg, err = Aggregate(pp, f.roots, f.rows)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *fixture) own(i int) []*big.Int { return []*big.Int{f.deltas[0][i], f.deltas[1][i]} }
func fixedCipher(t *Target) (*Ciphertext, []byte) {
	c := t.Params.Ctx
	s := big.NewInt(7)
	ct := &Ciphertext{C0: c.SourceScale(t.Params.G, s), C1: c.SourceScale(t.P, s), Context: append([]byte(nil), t.Context...), Version: t.Version, PreparedID: t.PreparedID}
	return ct, deriveKey(ct, c.TargetScale(t.Params.Z, s))
}
func fixedTarget(t *testing.T, a *Prepared, policy []Literal) *Target {
	t.Helper()
	w := make([]*big.Int, len(policy))
	for i := range w {
		w[i] = big.NewInt(int64(i + 2))
	}
	out, err := targetWithWeights(a, policy, w, []byte("test-snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFourClassesAndNegativeLiterals(t *testing.T) {
	f := newFixture(t, 4)
	policies := [][]Literal{{{Basis: 0}}, {{Basis: 1}}, {{Basis: 0}, {Basis: 1}}, {{Basis: 0, Negative: true}}, {{Basis: 1, Negative: true}}, {{Basis: 0}, {Basis: 1, Negative: true}}}
	for _, policy := range policies {
		target := fixedTarget(t, f.agg, policy)
		ct, key := fixedCipher(target)
		for i := 0; i < 4; i++ {
			h, err := Help(f.agg, i)
			if err != nil {
				t.Fatal(err)
			}
			if err = VerifyHelp(f.agg, h); err != nil {
				t.Fatal(err)
			}
			got, err := Decapsulate(target, ct, f.users[i], f.own(i), h)
			if err != nil {
				t.Fatal(err)
			}
			qual := true
			for _, lit := range policy {
				y := (i>>lit.Basis)&1 == 1
				if lit.Negative {
					y = !y
				}
				qual = qual && y
			}
			if bytes.Equal(got, key) != qual {
				t.Fatalf("slot %d policy %+v qualification %v", i, policy, qual)
			}
		}
	}
}

func TestAllCapacityCoordinatesValidated(t *testing.T) {
	f := newFixture(t, 4)
	bad := cloneRoot(f.roots[0])
	bad.Proj[2] = f.pp.Ctx.SourceAdd(bad.Proj[2], f.pp.G)
	if ValidateRoot(f.pp, bad) == nil {
		t.Fatal("changed high-capacity projection accepted")
	}
	r := cloneRow(f.rows[0][0])
	r.F[2] = f.pp.Ctx.SourceAdd(r.F[2], f.pp.G)
	if ValidateRow(f.pp, f.roots[0], r) == nil {
		t.Fatal("changed row projection accepted")
	}
	r = cloneRow(f.rows[0][0])
	r.Slot = 1
	if ValidateRow(f.pp, f.roots[0], r) == nil {
		t.Fatal("wrong slot accepted")
	}
	if _, err := Aggregate(f.pp, []*Root{f.roots[0], f.roots[0]}, nil); err == nil {
		t.Fatal("duplicate slot accepted")
	}
	if _, err := Aggregate(f.pp, nil, nil); err == nil {
		t.Fatal("empty cohort accepted")
	}
	wrongType := cloneRoot(f.roots[0])
	wrongType.Q = f.pp.Ctx.Pairing.NewGT().Set1()
	if ValidateRoot(f.pp, wrongType) == nil {
		t.Fatal("target-group reception key accepted")
	}
	wrongRow := cloneRow(f.rows[0][0])
	wrongRow.E = f.pp.Ctx.Pairing.NewGT().Set1()
	if ValidateRow(f.pp, f.roots[0], wrongRow) == nil {
		t.Fatal("target-group decision point accepted")
	}
}

func TestMomentHelpEqualsDirectPublicConstruction(t *testing.T) {
	f := newFixture(t, 4)
	c := f.pp.Ctx
	for i := 0; i < 4; i++ {
		h, err := Help(f.agg, i)
		if err != nil {
			t.Fatal(err)
		}
		for b := 0; b <= 2; b++ {
			expected := c.SourceZero()
			for j := 0; j < 4; j++ {
				if i == j {
					continue
				}
				l := f.agg.coeff[i]
				quot := make([]*big.Int, len(l)-1)
				quot[len(quot)-1] = new(big.Int).Set(l[len(l)-1])
				for k := len(quot) - 1; k >= 1; k-- {
					quot[k-1] = c.add(l[k], c.mul(f.pp.Nodes[j], quot[k]))
				}
				_, proj := f.agg.basis(b, j)
				for k, v := range quot {
					expected = c.SourceAdd(expected, c.SourceScale(proj[k], v))
				}
			}
			if !expected.Equals(h.Parts[b]) {
				t.Fatalf("moment/direct helper mismatch i=%d b=%d", i, b)
			}
		}
	}
}

func TestUpdateRetainsOldSnapshotAndBOnly(t *testing.T) {
	f := newFixture(t, 4)
	policy := []Literal{{Basis: 0}}
	oldTarget := fixedTarget(t, f.agg, policy)
	oldCT, oldKey := fixedCipher(oldTarget)
	oldHelp, err := Help(f.agg, 3)
	if err != nil {
		t.Fatal(err)
	}
	oldMasks := f.own(3)
	row, delta, err := Issue(f.pp, f.roots[3], false)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateRow(f.pp, f.roots[3], row); err != nil {
		t.Fatal(err)
	}
	if err = f.agg.UpdateRow(0, 3, row); err != nil {
		t.Fatal(err)
	}
	f.deltas[0][3] = delta
	got, err := Decapsulate(oldTarget, oldCT, f.users[3], oldMasks, oldHelp)
	if err != nil || !bytes.Equal(got, oldKey) {
		t.Fatalf("old retained authorized key lost: %v", err)
	}
	newTarget := fixedTarget(t, f.agg, policy)
	newCT, newKey := fixedCipher(newTarget)
	newHelp, err := Help(f.agg, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyHelp(f.agg, newHelp); err != nil {
		t.Fatal(err)
	}
	got, err = Decapsulate(newTarget, newCT, f.users[3], f.own(3), newHelp)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, newKey) {
		t.Fatal("denied A still recovers new fixed-nondegenerate key")
	}
	if _, err = Decapsulate(newTarget, newCT, f.users[3], f.own(3), oldHelp); err == nil {
		t.Fatal("old helper accepted for new version")
	}
	bt := fixedTarget(t, f.agg, []Literal{{Basis: 1}})
	bc, bk := fixedCipher(bt)
	got, err = Decapsulate(bt, bc, f.users[3], f.own(3), newHelp)
	if err != nil || !bytes.Equal(got, bk) {
		t.Fatalf("B-only access lost: %v", err)
	}
}

func TestRogueRootKnownBadWeight(t *testing.T) {
	f := newFixture(t, 2)
	c := f.pp.Ctx
	rogue := cloneRoot(f.roots[0])
	rogue.V = c.SourceNeg(f.pp.W[0])
	for k := range rogue.Proj {
		rogue.Proj[k] = c.SourceNeg(f.pp.B[k])
	}
	if err := ValidateRoot(f.pp, rogue); err != nil {
		t.Fatal(err)
	}
	r0, d0, err := Issue(f.pp, rogue, false)
	if err != nil {
		t.Fatal(err)
	}
	r1, d1, err := Issue(f.pp, f.roots[1], true)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Aggregate(f.pp, []*Root{rogue, f.roots[1]}, [][]*Row{{r0, r1}})
	if err != nil {
		t.Fatal(err)
	}
	h0, _ := Help(a, 0)
	h1, _ := Help(a, 1)
	for _, w := range []int64{1, 2} {
		target, err := targetWithWeights(a, []Literal{{Basis: 0}}, []*big.Int{big.NewInt(w)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		ct, key := fixedCipher(target)
		got, err := DecapsulateWithCorrection(target, ct, c.mul(big.NewInt(w), d0), h0)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(got, key) != (w == 1) {
			t.Fatalf("rogue cancellation at weight %d incorrect", w)
		}
		got, err = Decapsulate(target, ct, f.users[1], []*big.Int{d1}, h1)
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("honest qualified receiver failed: %v", err)
		}
	}
}

func TestSingletonAndContextBinding(t *testing.T) {
	f := newFixture(t, 4)
	a, err := Aggregate(f.pp, []*Root{f.roots[3]}, [][]*Row{{f.rows[0][3]}, {f.rows[1][3]}})
	if err != nil {
		t.Fatal(err)
	}
	target := fixedTarget(t, a, []Literal{{Basis: 0}})
	ct, key := fixedCipher(target)
	h, err := Help(a, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyHelp(a, h); err != nil {
		t.Fatal(err)
	}
	got, err := Decapsulate(target, ct, f.users[3], f.own(3), h)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("singleton failed: %v", err)
	}
	ct.Context = append(ct.Context, 1)
	if _, err = Decapsulate(target, ct, f.users[3], f.own(3), h); err == nil {
		t.Fatal("wrong snapshot context accepted")
	}
}

func TestPreparationSourceWorkIndependentOfCohort(t *testing.T) {
	f := newFixture(t, 4)
	small, err := Aggregate(f.pp, f.roots[:2], [][]*Row{f.rows[0][:2], f.rows[1][:2]})
	if err != nil {
		t.Fatal(err)
	}
	policy := []Literal{{Basis: 0}, {Basis: 1, Negative: true}}
	f.pp.Ctx.ResetStats()
	_ = fixedTarget(t, small, policy)
	a := f.pp.Ctx.Stats().SourceOps
	f.pp.Ctx.ResetStats()
	_ = fixedTarget(t, f.agg, policy)
	b := f.pp.Ctx.Stats().SourceOps
	if a != b {
		t.Fatalf("policy preparation scans cohort in source arithmetic: %d vs %d", a, b)
	}
	// Full metadata copying/hashing still grows and is deliberately NOT called constant.
}

func TestCanonicalScalarsAndFullDomainZero(t *testing.T) {
	f := newFixture(t, 2)
	c := f.pp.Ctx
	for _, x := range []*big.Int{new(big.Int), new(big.Int).Sub(c.P, big.NewInt(1))} {
		b, err := c.ScalarBytes(x)
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.ParseScalar(b)
		if err != nil || got.Cmp(x) != 0 {
			t.Fatal("scalar round trip")
		}
	}
	if _, err := c.ScalarBytes(c.P); err == nil {
		t.Fatal("p encoded as canonical scalar")
	}
	if _, err := c.ParseScalar(c.P.FillBytes(make([]byte, c.ScalarSize()))); err == nil {
		t.Fatal("p parsed as canonical scalar")
	}
	c.rng = bytes.NewReader(make([]byte, 10))
	z, err := c.Sample(false)
	if err != nil || z.Sign() != 0 {
		t.Fatalf("full-domain zero rejected: %v", err)
	}
	r := issueWithDelta(f.pp, f.roots[0], false, new(big.Int))
	if err := ValidateRow(f.pp, f.roots[0], r); err != nil {
		t.Fatalf("zero mask invalid: %v", err)
	}
}

func TestMixedIssuerCoreCancellationRowIsAccepted(t *testing.T) {
	f := newFixture(t, 2)
	c := f.pp.Ctx
	r := cloneRow(f.rows[0][1])
	r.E = c.SourceNeg(f.roots[1].V)
	r.F = make([]*pbc.Element, f.pp.N-1)
	for k := range r.F {
		r.F[k] = c.SourceNeg(f.roots[1].Proj[k])
	}
	if err := ValidateRow(f.pp, f.roots[1], r); err != nil {
		t.Fatal(err)
	}
	// This is an algebraically accepted row, not a canonical honest Boolean decision.
}

func TestTamperedHelpRejectedByPublicVerification(t *testing.T) {
	f := newFixture(t, 4)
	h, err := Help(f.agg, 0)
	if err != nil {
		t.Fatal(err)
	}
	h.Parts[1] = f.pp.Ctx.SourceAdd(h.Parts[1], f.pp.G)
	if VerifyHelp(f.agg, h) == nil {
		t.Fatal("modified help passed public verification")
	}
}
