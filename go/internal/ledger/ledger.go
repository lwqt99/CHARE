package ledger

import (
	"errors"
	"math/big"
)

// Point describes sum_a Polynomial[a](tau)*w_a + sum_b Pads[b]*r_b.
// The known d_m(tau) term may be subtracted and is not part of these matrices.
type Point struct {
	Polynomial Matrix
	Pads       Vector
}

type Input struct {
	Modulus                *big.Int // designated setup prime; this package does not certify primality
	Nodes                  Vector   // distinct, nonzero public nodes; length is capacity N
	Slots                  []int    // immutable slot of each ordinary source, including historical ones
	PadCount               int
	NumericalW, NumericalR Matrix
	Points                 []Point
}

// Audit owns copies of all inputs. It does not read a holder's scalar, facts,
// delivery coins, discrete logarithms or any PBC handle.
type Audit struct {
	f            field
	nodes        Vector
	slots        []int
	pads         int
	lw, lr, p, b Matrix
	poly         []Matrix
	cap          Matrix
	t            reduction
}

func New(in Input) (*Audit, error) {
	if in.Modulus == nil || in.Modulus.Cmp(big.NewInt(2)) <= 0 || len(in.Nodes) < 2 || in.Modulus.Cmp(big.NewInt(int64(len(in.Nodes)+1))) <= 0 || in.PadCount < 0 {
		return nil, errors.New("require designated prime p>N+1, N>=2, nonnegative pads")
	}
	a := &Audit{f: field{new(big.Int).Set(in.Modulus)}, pads: in.PadCount, slots: append([]int(nil), in.Slots...)}
	f := a.f
	n, d, s, q := len(in.Nodes), len(in.Slots), len(in.NumericalW), len(in.Points)
	if !f.vector(in.Nodes, n) || !f.shape(in.NumericalW, s, d) || !f.shape(in.NumericalR, s, in.PadCount) {
		return nil, errors.New("noncanonical scalar or matrix dimension")
	}
	seen := map[string]bool{}
	for _, t := range in.Nodes {
		if t.Sign() == 0 || seen[t.String()] {
			return nil, errors.New("zero or repeated node")
		}
		seen[t.String()] = true
	}
	for _, i := range in.Slots {
		if i < 0 || i >= n {
			return nil, errors.New("source slot outside capacity")
		}
	}
	a.nodes = clone(in.Nodes)
	a.lw = matrix(s, d)
	a.lr = matrix(s, in.PadCount)
	for i := 0; i < s; i++ {
		a.lw[i] = clone(in.NumericalW[i])
		a.lr[i] = clone(in.NumericalR[i])
	}
	a.p = matrix(q, d)
	a.b = matrix(q, in.PadCount)
	a.poly = make([]Matrix, q)
	for j, point := range in.Points {
		if !f.shape(point.Polynomial, d, n) || !f.vector(point.Pads, in.PadCount) {
			return nil, errors.New("point dimension or noncanonical coefficient")
		}
		a.poly[j] = matrix(d, n)
		a.b[j] = clone(point.Pads)
		for k, coefs := range point.Polynomial {
			a.poly[j][k] = clone(coefs)
			v := new(big.Int)
			for r := n - 1; r >= 0; r-- {
				v = f.add(f.mul(v, a.nodes[a.slots[k]]), coefs[r])
			}
			a.p[j][k] = v
		}
	}
	var capRows Matrix
	// Only pad-free numerical rows are localized by slot.
	numNull, err := f.null(trans(a.lr, a.pads), s)
	if err != nil {
		return nil, err
	}
	for _, c := range numNull {
		v := f.product(Matrix{c}, a.lw, d)[0]
		for i := 0; i < n; i++ {
			u := zeros(d)
			for k, slot := range a.slots {
				if slot == i {
					u[k].Set(v[k])
				}
			}
			capRows = append(capRows, u)
		}
	}
	// Whole points and scalar lifts cancel pads jointly; do not localize these.
	tPads := append(append(Matrix{}, a.b...), a.lr...)
	combined := append(append(Matrix{}, a.p...), a.lw...)
	mixedNull, err := f.null(trans(tPads, a.pads), q+s)
	if err != nil {
		return nil, err
	}
	capRows = append(capRows, f.product(mixedNull, combined, d)...)
	r, err := f.reduce(capRows, d, false)
	if err != nil {
		return nil, err
	}
	a.cap = matrix(len(r.pivots), d)
	for i := range a.cap {
		a.cap[i] = clone(r.r[i])
	}
	// Fact equations order is numerical rows, then whole points.
	a.t, err = f.reduce(append(append(Matrix{}, a.lr...), a.b...), a.pads, true)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Audit) Capability() Matrix {
	out := matrix(len(a.cap), len(a.slots))
	for i := range out {
		out[i] = clone(a.cap[i])
	}
	return out
}

type FactFailure struct {
	Kind  string // "pole" or "polynomial"
	Index int    // public slot index or polynomial coefficient degree
	Left  Vector // numerical rows first, then whole-point rows
	RHS   Vector // Left*RHS=1, Left*T=0
}
type FactResult struct {
	Compatible                         bool
	PolePreimages, PolynomialPreimages Matrix // v_i and v_k, not their negative beta scaling
	Failure                            *FactFailure
}

// Facts takes the explicit original-fact difference A_t*d, not a new pair
// chosen after an opening. It cannot establish source provenance or history
// admissibility; those are separate proof and application conditions.
func (a *Audit) Facts(shift Vector) (FactResult, error) {
	f := a.f
	n, d, s, q := len(a.nodes), len(a.slots), len(a.lw), len(a.p)
	if !f.vector(shift, d) {
		return FactResult{}, errors.New("invalid semantic source shift")
	}
	out := FactResult{Compatible: true, PolePreimages: matrix(n, a.pads), PolynomialPreimages: matrix(n-1, a.pads)}
	check := func(kind string, index int, rhs Vector) (Vector, bool, error) {
		x, dual, err := f.solve(a.t, rhs)
		if err != nil {
			return nil, false, err
		}
		if dual != nil {
			out.Compatible = false
			out.Failure = &FactFailure{kind, index, dual, clone(rhs)}
			return nil, false, nil
		}
		return x, true, nil
	}
	for i := 0; i < n; i++ {
		rhs := zeros(s + q)
		for k, slot := range a.slots {
			if slot != i {
				continue
			}
			for j := 0; j < s; j++ {
				rhs[j] = f.add(rhs[j], f.mul(a.lw[j][k], shift[k]))
			}
			for j := 0; j < q; j++ {
				rhs[s+j] = f.add(rhs[s+j], f.mul(a.p[j][k], shift[k]))
			}
		}
		x, ok, err := check("pole", i, rhs)
		if err != nil || !ok {
			return out, err
		}
		out.PolePreimages[i] = x
	}
	// Synthetic division p(X)=p(t)+(X-t)q(X); fixed degree N-1.
	quot := make([]Matrix, q)
	for j := 0; j < q; j++ {
		quot[j] = matrix(d, n-1)
		for k := 0; k < d; k++ {
			quot[j][k][n-2].Set(a.poly[j][k][n-1])
			for r := n - 3; r >= 0; r-- {
				quot[j][k][r] = f.add(a.poly[j][k][r+1], f.mul(a.nodes[a.slots[k]], quot[j][k][r+1]))
			}
		}
	}
	for r := 0; r < n-1; r++ {
		rhs := zeros(s + q)
		for j := 0; j < q; j++ {
			for k := 0; k < d; k++ {
				rhs[s+j] = f.add(rhs[s+j], f.mul(quot[j][k][r], shift[k]))
			}
		}
		x, ok, err := check("polynomial", r, rhs)
		if err != nil || !ok {
			return out, err
		}
		out.PolynomialPreimages[r] = x
	}
	return out, nil
}

type MessageResult struct {
	Protected      bool
	RowCertificate Vector // gamma = coefficients * (diag(eta); H*F)
	Recovery       Vector // otherwise diag(eta)*x=0, H*F*x=0, gamma*x=1
	Annihilator    Matrix // H; kernel H equals the capability space
}

// Message is an explicit-coefficient theorem diagnostic. eta may encode hidden
// facts: it must NOT be queried by a public directory pretending to know them.
// A Recovery vector is a formal coefficient witness, not a discrete-log oracle.
func (a *Audit) Message(F Matrix, eta, gamma Vector) (MessageResult, error) {
	f := a.f
	d, n := len(a.slots), len(eta)
	if n == 0 || n > len(a.nodes) || !f.vector(eta, n) || !f.vector(gamma, n) || !f.shape(F, d, n) {
		return MessageResult{}, errors.New("invalid target coefficient dimensions")
	}
	for _, g := range gamma {
		if g.Sign() == 0 {
			return MessageResult{}, errors.New("zero interpolation coefficient")
		}
	}
	h, err := f.null(a.cap, d)
	if err != nil {
		return MessageResult{}, err
	}
	b := matrix(n, n)
	for i := range eta {
		b[i][i].Set(eta[i])
	}
	b = append(b, f.product(h, F, n)...)
	r, err := f.reduce(trans(b, n), len(b), true)
	if err != nil {
		return MessageResult{}, err
	}
	z, x, err := f.solve(r, gamma)
	if err != nil {
		return MessageResult{}, err
	}
	return MessageResult{Protected: x == nil, RowCertificate: z, Recovery: x, Annihilator: h}, nil
}

// PublicCertificate implements only D=empty: no hidden residual input.
// Failure is inconclusive, NOT a proof of recovery or an unqualified user.
func (a *Audit) PublicCertificate(F Matrix, gamma Vector) (z Vector, found bool, err error) {
	r, err := a.Message(F, zeros(len(gamma)), gamma)
	if err != nil {
		return nil, false, err
	}
	if !r.Protected {
		return nil, false, nil
	}
	z = zeros(len(a.slots))
	n := len(gamma)
	for j, h := range r.Annihilator {
		for k := range z {
			z[k] = a.f.add(z[k], a.f.mul(r.RowCertificate[n+j], h[k]))
		}
	}
	return z, true, nil
}
