package ledger

import (
	"math/big"
	"testing"
)

func vec(xs ...int64) Vector {
	r := zeros(len(xs))
	for i, x := range xs {
		r[i].SetInt64(x)
	}
	return r
}
func base(n int, slots ...int) Input {
	nodes := zeros(n)
	for i := range nodes {
		nodes[i].SetInt64(int64(i + 1))
	}
	return Input{Modulus: big.NewInt(101), Nodes: nodes, Slots: slots}
}
func must(t *testing.T, in Input) *Audit {
	t.Helper()
	a, err := New(in)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func zero(v *big.Int) bool { return v.Sign() == 0 }
func identity(n int) Matrix {
	r := matrix(n, n)
	for i := range r {
		r[i][i].SetInt64(1)
	}
	return r
}
func gamma(f field, nodes Vector) Vector {
	r := zeros(len(nodes))
	for i := range nodes {
		d := big.NewInt(1)
		for j := range nodes {
			if i != j {
				d = f.mul(d, f.sub(nodes[i], nodes[j]))
			}
		}
		r[i] = new(big.Int).ModInverse(d, f.p)
	}
	return r
}
func assertMessage(t *testing.T, a *Audit, F Matrix, eta, g Vector, w MessageResult) {
	t.Helper()
	h := w.Annihilator
	hf := a.f.product(h, F, len(eta))
	if w.Protected {
		b := matrix(len(eta), len(eta))
		for i := range eta {
			b[i][i].Set(eta[i])
		}
		b = append(b, hf...)
		got := a.f.product(Matrix{w.RowCertificate}, b, len(eta))[0]
		for i := range got {
			if got[i].Cmp(g[i]) != 0 {
				t.Fatal("invalid protection row certificate")
			}
		}
	} else {
		for i := range eta {
			if !zero(a.f.mul(eta[i], w.Recovery[i])) {
				t.Fatal("residual witness")
			}
		}
		for _, row := range hf {
			if !zero(a.f.dot(row, w.Recovery)) {
				t.Fatal("capability witness")
			}
		}
		if a.f.dot(g, w.Recovery).Cmp(big.NewInt(1)) != 0 {
			t.Fatal("unnormalized recovery")
		}
	}
}

func TestScalarLocalizationDiffersFromWholePoint(t *testing.T) {
	in := base(2, 0, 1)
	in.Points = []Point{{Polynomial: Matrix{vec(1, 0), vec(1, 0)}, Pads: Vector{}}}
	point := must(t, in)
	in.Points = nil
	in.NumericalW = Matrix{vec(1, 1)}
	in.NumericalR = Matrix{Vector{}}
	scalar := must(t, in)
	if len(point.Capability()) != 1 || len(scalar.Capability()) != 2 {
		t.Fatal("whole point incorrectly localized")
	}
	f := identity(2)
	eta := vec(0, 0)
	g := vec(100, 1)
	for _, a := range []*Audit{point, scalar} {
		r, err := a.Message(f, eta, g)
		if err != nil {
			t.Fatal(err)
		}
		assertMessage(t, a, f, eta, g, r)
		if r.Protected != (a == point) {
			t.Fatal("wrong coupling decision")
		}
	}
	z, found, err := point.PublicCertificate(f, g)
	if err != nil || !found {
		t.Fatal("public certificate missing", err)
	}
	if !zero(point.f.dot(point.cap[0], z)) || z[0].Cmp(g[0]) != 0 || z[1].Cmp(g[1]) != 0 {
		t.Fatal("bad public z")
	}
}

func TestMixedPadsCancelBeforeAnyLocalization(t *testing.T) {
	in := base(2, 0, 1)
	in.PadCount = 1
	in.NumericalW = Matrix{vec(1, 0)}
	in.NumericalR = Matrix{vec(1)}
	in.Points = []Point{{Polynomial: Matrix{vec(0, 0), vec(1, 0)}, Pads: vec(1)}}
	a := must(t, in)
	if len(a.cap) != 1 || !zero(a.f.dot(a.cap[0], vec(1, 1))) {
		t.Fatal("mixed capability was localized or pad lost")
	}
	g := vec(100, 1)
	r, err := a.Message(identity(2), vec(0, 0), g)
	if err != nil {
		t.Fatal(err)
	}
	if r.Protected {
		t.Fatal("actual mixed difference lost")
	}
	assertMessage(t, a, identity(2), vec(0, 0), g, r)
}

func TestPolynomialPartDetectsResidueInvisibleFact(t *testing.T) {
	in := base(2, 0)
	in.PadCount = 1
	in.Points = []Point{{Polynomial: Matrix{vec(100, 1)}, Pads: vec(1)}, {Polynomial: Matrix{vec(0, 0)}, Pads: vec(100)}}
	a := must(t, in)
	if len(a.cap) != 0 {
		t.Fatal("polynomial multiple has nonzero residue")
	}
	r, err := a.Facts(vec(1))
	if err != nil {
		t.Fatal(err)
	}
	if r.Compatible || r.Failure == nil || r.Failure.Kind != "polynomial" || r.Failure.Index != 0 {
		t.Fatal("missed polynomial fact failure")
	}
	w := r.Failure
	if !zero(a.f.dot(w.Left, vec(1, 100))) || a.f.dot(w.Left, w.RHS).Cmp(big.NewInt(1)) != 0 {
		t.Fatal("invalid dual fact witness")
	}
}

func TestCompatiblePadPreimagesAndPublicFailureIsInconclusive(t *testing.T) {
	in := base(2, 0)
	in.PadCount = 1
	in.Points = []Point{{Polynomial: Matrix{vec(100, 1)}, Pads: vec(1)}}
	a := must(t, in)
	r, err := a.Facts(vec(1))
	if err != nil || !r.Compatible {
		t.Fatal(r, err)
	}
	if r.PolePreimages[0][0].Sign() != 0 || r.PolynomialPreimages[0][0].Cmp(big.NewInt(1)) != 0 {
		t.Fatal("wrong pad displacement")
	}
	known := base(2, 0, 1)
	known.NumericalW = identity(2)
	known.NumericalR = Matrix{Vector{}, Vector{}}
	b := must(t, known)
	g := vec(100, 1)
	m, err := b.Message(identity(2), vec(2, 3), g)
	if err != nil || !m.Protected {
		t.Fatal("nonzero refusals should block", err)
	}
	if _, found, err := b.PublicCertificate(identity(2), g); err != nil || found {
		t.Fatal("D=empty falsely certified known sources", err)
	}
}

func TestFourClassMessageWitnessesIncludeHonestQualifiedCore(t *testing.T) {
	in := base(4, 0, 1, 2, 3)
	in.NumericalW = identity(4)[:3]
	in.NumericalR = Matrix{Vector{}, Vector{}, Vector{}}
	a := must(t, in)
	f := identity(4)
	g := gamma(a.f, a.nodes)
	eta := vec(5, 3, 2, 0)
	r, err := a.Message(f, eta, g)
	if err != nil || !r.Protected {
		t.Fatal("base obstruction absent", err)
	}
	assertMessage(t, a, f, eta, g, r)
	eta[0].SetInt64(0) // explicit bad-weight residual, not resampling or hidden branching
	r, err = a.Message(f, eta, g)
	if err != nil || r.Protected {
		t.Fatal("bad residual lacks witness", err)
	}
	assertMessage(t, a, f, eta, g, r)
}

func TestCanonicalDimensionsAndSnapshotOwnership(t *testing.T) {
	in := base(2, 0)
	in.NumericalW = Matrix{vec(1)}
	in.NumericalR = Matrix{Vector{}}
	a := must(t, in)
	in.NumericalW[0][0].SetInt64(0)
	in.Nodes[0].SetInt64(0)
	in.Modulus.SetInt64(7)
	if len(a.cap) != 1 || a.nodes[0].Cmp(big.NewInt(1)) != 0 || a.f.p.Cmp(big.NewInt(101)) != 0 {
		t.Fatal("retained input alias")
	}
	copy := a.Capability()
	copy[0][0].SetInt64(0)
	if a.cap[0][0].Sign() == 0 {
		t.Fatal("output aliases audit")
	}
	for _, x := range []*big.Int{nil, big.NewInt(-1), big.NewInt(101), big.NewInt(127)} {
		bad := base(2, 0)
		bad.NumericalW = Matrix{Vector{x}}
		bad.NumericalR = Matrix{Vector{}}
		if _, err := New(bad); err == nil {
			t.Fatal("invalid scalar accepted")
		}
	}
	bad := base(2, 0)
	bad.Points = []Point{{Polynomial: Matrix{vec(1)}, Pads: Vector{}}}
	if _, err := New(bad); err == nil {
		t.Fatal("truncated polynomial accepted")
	}
	bad = base(2, 2)
	if _, err := New(bad); err == nil {
		t.Fatal("out-of-range slot")
	}
	bad = base(2, 0)
	bad.Nodes[1].Set(bad.Nodes[0])
	if _, err := New(bad); err == nil {
		t.Fatal("duplicate node")
	}
	if _, err := a.Facts(vec(101)); err == nil {
		t.Fatal("noncanonical fact shift")
	}
	if _, err := a.Message(Matrix{vec(1)}, vec(0), vec(0)); err == nil {
		t.Fatal("zero gamma")
	}
}

func TestEmptyObservationsAndScalarFactOpening(t *testing.T) {
	a := must(t, base(2, 0))
	r, err := a.Facts(vec(100))
	if err != nil || !r.Compatible {
		t.Fatal("empty history", err)
	}
	if len(a.cap) != 0 {
		t.Fatal("empty history has capability")
	}
	in := base(2, 0)
	in.NumericalW = Matrix{vec(1)}
	in.NumericalR = Matrix{Vector{}}
	b := must(t, in)
	r, err = b.Facts(vec(1))
	if err != nil || r.Compatible || r.Failure.Kind != "pole" {
		t.Fatal("opened changed mask accepted", err)
	}
	r, err = b.Facts(vec(0))
	if err != nil || !r.Compatible {
		t.Fatal("matched opening rejected", err)
	}
}

func TestHighDegreeQuotientAndJointPadConstraints(t *testing.T) {
	in := base(4, 1)
	in.PadCount = 2
	in.NumericalW = Matrix{vec(0)}
	in.NumericalR = Matrix{vec(1, 1)}
	// (X-2)*(3+4X+5X^2) = -6-5X-6X^2+5X^3.
	in.Points = []Point{{Polynomial: Matrix{vec(95, 96, 95, 5)}, Pads: vec(1, 0)}}
	a := must(t, in)
	r, err := a.Facts(vec(1))
	if err != nil || !r.Compatible {
		t.Fatal(err)
	}
	for k, want := range []int64{3, 4, 5} {
		v := r.PolynomialPreimages[k]
		if !zero(a.f.dot(vec(1, 1), v)) || a.f.dot(vec(1, 0), v).Cmp(big.NewInt(want)) != 0 {
			t.Fatal("joint scalar/point polynomial solve")
		}
	}
}
