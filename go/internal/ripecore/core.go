package ripecore

import (
	"errors"
	"fmt"
	"math/big"
)

var ErrSetupDegenerate = errors.New("RIPE one-shot setup has a publicly detected degeneracy")
var ErrKeyAttempts = errors.New("RIPE key normalization retry budget exhausted")
var ErrUnqualified = errors.New("receiver lacks a selected requested qualification")

// Parameters preserve the original zero slot and every off-diagonal W entry.
// U[coordinate][source], W[receiver-1][source][coordinate]; the own-source
// W slice is nil and must never be materialized as a public self projection.
type Parameters struct {
	c            *Context
	ready        bool
	N, M         int
	U            [][]G1
	W            [][][]G2
	V, B         []G2
	P0           []G2
	T0, H, Gamma G1
	Z            GT
}

func (p *Parameters) a() int   { return p.M }
func (p *Parameters) b() int   { return p.M + 1 }
func (p *Parameters) cc() int  { return p.M + 2 }
func (p *Parameters) rr() int  { return p.M + 4 }
func (p *Parameters) dim() int { return p.M + 5 }

type setupCoins struct {
	alpha, beta, gamma *big.Int
	t                  []*big.Int
	u                  [][]*big.Int
	dummy              []*big.Int
}

func Setup(c *Context, n, m int) (*Parameters, error) {
	if c == nil || n < 2 || n > 4096 || m < 1 || m > 64 || c.p.Cmp(big.NewInt(int64(m+2))) <= 0 {
		return nil, errors.New("invalid RIPE dimensions")
	}
	d := m + 5
	s := setupCoins{t: make([]*big.Int, n), u: make([][]*big.Int, d), dummy: make([]*big.Int, d)}
	var err error
	for _, dst := range []**big.Int{&s.alpha, &s.beta, &s.gamma} {
		*dst, err = c.sample(true)
		if err != nil {
			return nil, err
		}
	}
	for i := range s.t {
		s.t[i], err = c.sample(false)
		if err != nil {
			return nil, err
		}
	}
	for w := range s.u {
		s.u[w] = make([]*big.Int, n+1)
		for i := range s.u[w] {
			s.u[w][i], err = c.sample(false)
			if err != nil {
				return nil, err
			}
		}
	}
	// Uniform nonzero vector by its base-p integer representation, preserving
	// the joint law with the subsequently computed correlated dummy inner product.
	bound := new(big.Int).Sub(new(big.Int).Exp(c.p, big.NewInt(int64(d)), nil), big.NewInt(1))
	x, err := randBelow(c, bound)
	if err != nil {
		return nil, err
	}
	x.Add(x, big.NewInt(1))
	for w := range s.dummy {
		q, r := new(big.Int), new(big.Int)
		q.QuoRem(x, c.p, r)
		s.dummy[w] = r
		x = q
	}
	return setupWithCoins(c, n, m, s)
}

func setupWithCoins(c *Context, n, m int, s setupCoins) (*Parameters, error) {
	d := m + 5
	if n < 2 || m < 1 || len(s.t) != n || len(s.u) != d || len(s.dummy) != d {
		return nil, errors.New("bad setup tape shape")
	}
	for _, x := range []*big.Int{s.alpha, s.beta, s.gamma} {
		if !c.valid(x) || x.Sign() == 0 {
			return nil, errors.New("invalid nonzero setup scalar")
		}
	}
	for _, x := range s.t {
		if !c.valid(x) {
			return nil, errors.New("invalid t")
		}
	}
	nonzero := false
	for w := 0; w < d; w++ {
		if len(s.u[w]) != n+1 || !c.valid(s.dummy[w]) {
			return nil, errors.New("invalid dummy tape")
		}
		nonzero = nonzero || s.dummy[w].Sign() != 0
		for _, x := range s.u[w] {
			if !c.valid(x) {
				return nil, errors.New("invalid u")
			}
		}
	}
	if !nonzero {
		return nil, errors.New("source dummy vector must be nonzero")
	}
	p := &Parameters{c: c, N: n, M: m, U: make([][]G1, d), W: make([][][]G2, n), V: make([]G2, n), B: make([]G2, n), P0: make([]G2, n)}
	p.H = c.Scale1(c.g1, s.beta)
	p.Gamma = c.Scale1(c.g1, s.gamma)
	p.Z = c.ScaleT(c.base, s.alpha)
	D := big.NewInt(0)
	for w := 0; w < d; w++ {
		p.U[w] = make([]G1, n+1)
		for i := 0; i <= n; i++ {
			p.U[w][i] = c.Scale1(c.g1, s.u[w][i])
		}
		D = c.add(D, c.mul(s.u[w][0], s.dummy[w]))
	}
	p.T0 = c.Scale1(c.g1, c.neg(D))
	inv := new(big.Int).ModInverse(s.gamma, c.p)
	for j := 0; j < n; j++ {
		p.V[j] = c.Scale2(c.g2, s.t[j])
		p.B[j] = c.Scale2(c.g2, c.add(s.alpha, c.mul(s.beta, s.t[j])))
		factor := c.mul(s.t[j], inv)
		p.P0[j] = c.Scale2(c.g2, c.mul(factor, D))
		p.W[j] = make([][]G2, n+1)
		for i := 0; i <= n; i++ {
			if i == j+1 {
				continue
			}
			p.W[j][i] = make([]G2, d)
			for w := 0; w < d; w++ {
				p.W[j][i][w] = c.Scale2(c.g2, c.mul(factor, s.u[w][i]))
			}
		}
	}
	// A single actual setup, not rejection of an external CRS followed by retry.
	for i := 1; i <= n; i++ {
		if p.V[i-1].e.Is0() || p.U[p.rr()][i].e.Is0() || p.U[p.b()][i].Equal(p.U[p.cc()][i]) {
			return p, ErrSetupDegenerate
		}
	}
	p.ready = true
	return p, nil
}

type RawKey struct {
	p    *Parameters
	Slot int
	T    G1
	P    []G2
}
type KeySecret struct {
	p    *Parameters
	slot int
	r    *big.Int
}
type KeyAttempt struct {
	Raw      *RawKey
	Accepted bool
}

func rawKey(p *Parameters, slot int, r *big.Int) (*RawKey, *KeySecret, error) {
	if p == nil || slot < 1 || slot > p.N || !p.c.valid(r) || r.Sign() == 0 {
		return nil, nil, errors.New("invalid canonical raw key")
	}
	c := p.c
	k := &RawKey{p: p, Slot: slot, T: c.Scale1(p.U[p.rr()][slot], c.neg(r)), P: make([]G2, p.N)}
	for j := 0; j < p.N; j++ {
		if j+1 != slot {
			k.P[j] = c.Scale2(p.W[j][slot][p.rr()], r)
		}
	}
	return k, &KeySecret{p: p, slot: slot, r: new(big.Int).Set(r)}, nil
}

// UserKeyGen retains every attempted public object; it never returns setup
// secrets. The accepted secret is local receiver state, not a registration
// opening demanded of an adversary. The whole certified proof layer is absent.
func UserKeyGen(p *Parameters, slot, maxAttempts int) (*RawKey, *KeySecret, []KeyAttempt, error) {
	if p == nil {
		return nil, nil, nil, errors.New("nil parameters")
	}
	return userKeyGen(p, slot, maxAttempts, func() (*big.Int, error) { return p.c.sample(true) })
}
func userKeyGen(p *Parameters, slot, maxAttempts int, draw func() (*big.Int, error)) (*RawKey, *KeySecret, []KeyAttempt, error) {
	if p == nil || !p.ready || slot < 1 || slot > p.N || maxAttempts < 1 || maxAttempts > 1<<20 {
		return nil, nil, nil, errors.New("invalid key request")
	}
	attempts := make([]KeyAttempt, 0, maxAttempts)
	for a := 0; a < maxAttempts; a++ {
		r, err := draw()
		if err != nil {
			return nil, nil, attempts, err
		}
		k, s, err := rawKey(p, slot, r)
		if err != nil {
			return nil, nil, attempts, err
		}
		ok := !p.c.Add1(p.c.Scale1(p.U[p.rr()][slot], big.NewInt(int64(p.M+2))), p.c.Neg1(k.T)).e.Is0()
		attempts = append(attempts, KeyAttempt{k, ok})
		if ok {
			return k, s, attempts, nil
		}
	}
	return nil, nil, attempts, ErrKeyAttempts
}

// CheckKeyProjections is source IsValid plus the public normalization checks.
// It is deliberately NOT named Register or VerifyProof: an unknown scalar
// may pass this check, and source IsValid alone is not the proved system game.
func CheckKeyProjections(p *Parameters, k *RawKey) error {
	if p == nil || !p.ready || k == nil || k.p != p || k.Slot < 1 || k.Slot > p.N || len(k.P) != p.N || !p.c.owns1(k.T) {
		return errors.New("invalid raw-key shape")
	}
	c := p.c
	i := k.Slot
	if k.T.e.Is0() || c.Add1(c.Scale1(p.U[p.rr()][i], big.NewInt(int64(p.M+2))), c.Neg1(k.T)).e.Is0() {
		return errors.New("zero key or normalization")
	}
	for j := 0; j < p.N; j++ {
		if j+1 == i {
			if k.P[j].e != nil {
				return errors.New("self projection is forbidden")
			}
			continue
		}
		if !c.owns2(k.P[j]) || k.P[j].e.Is0() {
			return errors.New("missing/zero key projection")
		}
		if !c.Pair(c.Neg1(k.T), p.W[j][i][p.rr()]).Equal(c.Pair(p.U[p.rr()][i], k.P[j])) {
			return fmt.Errorf("raw projection %d", j)
		}
	}
	return nil
}

type Increment struct {
	p               *Parameters
	Slot, Attribute int
	E               G1
	F               []G2
}
type IncrementSecret struct {
	p               *Parameters
	slot, attribute int
	y               bool
	d               *big.Int
}

func NewIncrement(p *Parameters, slot, a int, y bool) (*Increment, *IncrementSecret, error) {
	if p == nil {
		return nil, nil, errors.New("nil parameters")
	}
	d, err := p.c.sample(false)
	if err != nil {
		return nil, nil, err
	}
	return increment(p, slot, a, y, d)
}
func increment(p *Parameters, slot, a int, y bool, d *big.Int) (*Increment, *IncrementSecret, error) {
	if p == nil || !p.ready || slot < 1 || slot > p.N || a < 0 || a >= p.M || !p.c.valid(d) {
		return nil, nil, errors.New("invalid increment")
	}
	c := p.c
	E := c.Scale1(c.Add1(p.U[p.b()][slot], c.Neg1(p.U[p.cc()][slot])), d)
	if y {
		E = c.Add1(E, c.Add1(p.U[p.b()][slot], c.Neg1(p.U[a][slot])))
	}
	x := &Increment{p: p, Slot: slot, Attribute: a, E: c.Neg1(E), F: make([]G2, p.N)}
	for j := 0; j < p.N; j++ {
		if j+1 == slot {
			continue
		}
		v := c.Scale2(c.Add2(p.W[j][slot][p.b()], c.Neg2(p.W[j][slot][p.cc()])), d)
		if y {
			v = c.Add2(v, c.Add2(p.W[j][slot][p.b()], c.Neg2(p.W[j][slot][a])))
		}
		x.F[j] = v
	}
	return x, &IncrementSecret{p: p, slot: slot, attribute: a, y: y, d: new(big.Int).Set(d)}, nil
}
func CheckIncrementProjections(p *Parameters, x *Increment) error {
	if p == nil || !p.ready || x == nil || x.p != p || x.Slot < 1 || x.Slot > p.N || x.Attribute < 0 || x.Attribute >= p.M || len(x.F) != p.N || !p.c.owns1(x.E) {
		return errors.New("invalid increment shape")
	}
	c := p.c
	for j := 0; j < p.N; j++ {
		if j+1 == x.Slot {
			if x.F[j].e != nil {
				return errors.New("self increment forbidden")
			}
			continue
		}
		if !c.owns2(x.F[j]) || !c.Pair(c.Neg1(x.E), p.V[j]).Equal(c.Pair(p.Gamma, x.F[j])) {
			return fmt.Errorf("increment projection %d", j)
		}
	}
	return nil
}

type Prepared struct {
	p      *Parameters
	p0     G1
	pa     []G1
	jc, jr G1
	helps  []*Help
	rows   [][]*Increment // private immutable copies; never a source-secret store
}
type Help struct {
	prepared *Prepared
	slot     int
	k0       G2
	ka       []G2
	kc, kr   G2
	active   []bool
}

// Prepare receives PUBLIC keys, increments and selectors only. Full capacity,
// canonical order and all inactive coordinates are checked. This algebra-only
// API does not certify hidden facts or accept a missing proof as valid.
func Prepare(p *Parameters, keys []*RawKey, rows [][]*Increment, active [][]bool) (*Prepared, error) {
	if p == nil || len(keys) != p.N || len(rows) != p.N || len(active) != p.N {
		return nil, errors.New("capacity mismatch")
	}
	for i := 0; i < p.N; i++ {
		if keys[i] == nil || keys[i].Slot != i+1 {
			return nil, errors.New("key order")
		}
		if err := CheckKeyProjections(p, keys[i]); err != nil {
			return nil, err
		}
		if len(rows[i]) != p.M || len(active[i]) != p.M {
			return nil, errors.New("attribute shape")
		}
		for a := 0; a < p.M; a++ {
			x := rows[i][a]
			if x == nil || x.Slot != i+1 || x.Attribute != a {
				return nil, errors.New("row order")
			}
			if err := CheckIncrementProjections(p, x); err != nil {
				return nil, err
			}
		}
	}
	c := p.c
	d := p.dim()
	ub := make([]G1, d)
	for w := 0; w < d; w++ {
		ub[w] = c.zero1()
		for i := 0; i <= p.N; i++ {
			ub[w] = c.Add1(ub[w], p.U[w][i])
		}
	}
	tb := p.T0
	ta := make([]G1, p.M)
	for a := range ta {
		ta[a] = c.zero1()
	}
	for i := 0; i < p.N; i++ {
		v := c.Add1(keys[i].T, c.Neg1(p.U[p.a()][i+1]))
		for a := 0; a < p.M; a++ {
			v = c.Add1(v, c.Neg1(p.U[a][i+1]))
			if active[i][a] {
				ta[a] = c.Add1(ta[a], rows[i][a].E)
			}
		}
		tb = c.Add1(tb, v)
	}
	out := &Prepared{p: p, p0: c.Add1(ub[p.a()], tb), pa: make([]G1, p.M), jc: c.Add1(ub[p.cc()], c.Neg1(ub[p.b()])), jr: ub[p.rr()], helps: make([]*Help, p.N)}
	for a := 0; a < p.M; a++ {
		out.p0 = c.Add1(out.p0, ub[a])
		out.pa[a] = c.Add1(ta[a], c.Add1(ub[p.b()], c.Neg1(ub[a])))
	}
	for j := 0; j < p.N; j++ {
		hw := make([]G2, d)
		for w := 0; w < d; w++ {
			hw[w] = c.zero2()
			for i := 0; i <= p.N; i++ {
				if i != j+1 {
					hw[w] = c.Add2(hw[w], p.W[j][i][w])
				}
			}
		}
		pf := p.P0[j]
		fa := make([]G2, p.M)
		for a := range fa {
			fa[a] = c.zero2()
		}
		for i := 0; i < p.N; i++ {
			if i == j {
				continue
			}
			v := c.Add2(keys[i].P[j], p.W[j][i+1][p.a()])
			for a := 0; a < p.M; a++ {
				v = c.Add2(v, p.W[j][i+1][a])
				if active[i][a] {
					fa[a] = c.Add2(fa[a], rows[i][a].F[j])
				}
			}
			pf = c.Add2(pf, v)
		}
		h := &Help{prepared: out, slot: j + 1, k0: c.Add2(hw[p.a()], c.Neg2(pf)), ka: make([]G2, p.M), kc: c.Add2(hw[p.cc()], c.Neg2(hw[p.b()])), kr: hw[p.rr()], active: append([]bool(nil), active[j]...)}
		for a := 0; a < p.M; a++ {
			h.k0 = c.Add2(h.k0, hw[a])
			h.ka[a] = c.Add2(c.Neg2(fa[a]), c.Add2(hw[p.b()], c.Neg2(hw[a])))
		}
		out.helps[j] = h
	}
	out.rows = make([][]*Increment, p.N)
	for i := range rows {
		out.rows[i] = make([]*Increment, p.M)
		for a, x := range rows[i] {
			out.rows[i][a] = copyIncrement(x)
		}
	}
	return out, nil
}
func copyIncrement(x *Increment) *Increment { v := *x; v.F = append([]G2(nil), x.F...); return &v }

// ReplaceIncrement performs the existing public delta-cache update. Its input
// contains no receiver secret. It returns a new snapshot and keeps every old
// snapshot usable. Signature, proof, generation, expiration and currentness
// checks belong to the still-unimplemented certified wrapper.
func ReplaceIncrement(old *Prepared, row *Increment, active bool) (*Prepared, error) {
	if old == nil {
		return nil, errors.New("nil old prepared state")
	}
	p := old.p
	c := p.c
	if err := CheckIncrementProjections(p, row); err != nil {
		return nil, err
	}
	i, a := row.Slot-1, row.Attribute
	previous := old.rows[i][a]
	wasActive := old.helps[i].active[a]
	delta := c.zero1()
	if active {
		delta = c.Add1(delta, row.E)
	}
	if wasActive {
		delta = c.Add1(delta, c.Neg1(previous.E))
	}
	out := &Prepared{p: p, p0: old.p0, pa: append([]G1(nil), old.pa...), jc: old.jc, jr: old.jr, helps: make([]*Help, p.N), rows: append([][]*Increment(nil), old.rows...)}
	out.pa[a] = c.Add1(out.pa[a], delta)
	out.rows[i] = append([]*Increment(nil), old.rows[i]...)
	out.rows[i][a] = copyIncrement(row)
	for j, original := range old.helps {
		h := *original
		h.prepared = out
		h.ka = append([]G2(nil), original.ka...)
		h.active = append([]bool(nil), original.active...)
		if j == i {
			h.active[a] = active
		} else {
			d := c.zero2()
			if active {
				d = c.Add2(d, row.F[j])
			}
			if wasActive {
				d = c.Add2(d, c.Neg2(previous.F[j]))
			}
			h.ka[a] = c.Add2(h.ka[a], c.Neg2(d))
		}
		out.helps[j] = &h
	}
	return out, nil
}
func (a *Prepared) Help(slot int) (*Help, error) {
	if a == nil || slot < 1 || slot > a.p.N {
		return nil, errors.New("invalid help slot")
	}
	h := *a.helps[slot-1]
	h.ka = append([]G2(nil), h.ka...)
	h.active = append([]bool(nil), h.active...)
	return &h, nil
}

type Ciphertext struct {
	prepared           *Prepared
	policy             []bool
	CM                 GT
	CS, CZ, DP, DC, DR G1
}

func Encrypt(a *Prepared, policy []bool, message GT) (*Ciphertext, error) {
	if a == nil || len(policy) != a.p.M || !a.p.c.ownsT(message) {
		return nil, errors.New("invalid encryption input")
	}
	s, err := a.p.c.sample(true)
	if err != nil {
		return nil, err
	}
	z, err := a.p.c.sample(true)
	if err != nil {
		return nil, err
	}
	return encryptWithCoins(a, policy, message, s, z)
}
func encryptWithCoins(a *Prepared, policy []bool, message GT, s, z *big.Int) (*Ciphertext, error) {
	if a == nil || len(policy) != a.p.M || !a.p.c.ownsT(message) || !a.p.c.valid(s) || !a.p.c.valid(z) || s.Sign() == 0 || z.Sign() == 0 {
		return nil, errors.New("invalid source encryption coins")
	}
	p := a.p
	c := p.c
	v := a.p0
	for i, use := range policy {
		if use {
			v = c.Add1(v, a.pa[i])
		}
	}
	sh := c.Scale1(p.H, s)
	return &Ciphertext{prepared: a, policy: append([]bool(nil), policy...), CM: c.MulT(message, c.ScaleT(p.Z, s)), CS: c.Scale1(c.g1, s), CZ: c.Scale1(p.Gamma, z), DP: c.Add1(c.Scale1(sh, big.NewInt(int64(p.M+2))), c.Neg1(c.Scale1(v, z))), DC: c.Neg1(c.Scale1(a.jc, z)), DR: c.Add1(sh, c.Neg1(c.Scale1(a.jr, z)))}, nil
}
func Encapsulate(a *Prepared, policy []bool) (*Ciphertext, GT, error) {
	if a == nil {
		return nil, GT{}, errors.New("nil prepared state")
	}
	key, err := a.p.c.RandomMessage()
	if err != nil {
		return nil, GT{}, err
	}
	ct, err := Encrypt(a, policy, key)
	return ct, key, err
}

func Decapsulate(ct *Ciphertext, h *Help, secret *KeySecret, rows []*IncrementSecret) (GT, error) {
	if ct == nil || h == nil || secret == nil || ct.prepared == nil || h.prepared != ct.prepared || secret.p != ct.prepared.p || secret.slot != h.slot {
		return GT{}, errors.New("mixed local snapshot, parameters or receiver")
	}
	p := ct.prepared.p
	c := p.c
	if len(rows) != p.M || len(ct.policy) != p.M || len(h.active) != p.M || len(h.ka) != p.M {
		return GT{}, errors.New("receiver shape")
	}
	ci := big.NewInt(0)
	for a, x := range rows {
		if x == nil || x.p != p || x.slot != h.slot || x.attribute != a || !c.valid(x.d) {
			return GT{}, errors.New("receiver row mismatch")
		}
		if ct.policy[a] {
			if !h.active[a] || !x.y {
				return GT{}, ErrUnqualified
			}
			ci = c.add(ci, c.neg(x.d))
		}
	}
	X := c.add(secret.r, big.NewInt(int64(p.M+2)))
	inv := new(big.Int).ModInverse(X, c.p)
	if inv == nil {
		return GT{}, errors.New("zero normalization")
	}
	if !c.ownsT(ct.CM) || !c.owns1(ct.CS) || !c.owns1(ct.CZ) || !c.owns1(ct.DP) || !c.owns1(ct.DC) || !c.owns1(ct.DR) {
		return GT{}, errors.New("ciphertext type")
	}
	u := c.Add1(ct.DP, c.Add1(c.Scale1(ct.DC, ci), c.Scale1(ct.DR, secret.r)))
	v := h.k0
	for a, use := range ct.policy {
		if use {
			v = c.Add2(v, h.ka[a])
		}
	}
	v = c.Add2(v, c.Add2(c.Scale2(h.kc, ci), c.Scale2(h.kr, secret.r)))
	prod := c.MulT(c.Pair(u, p.V[h.slot-1]), c.Pair(ct.CZ, v))
	return c.MulT(c.DivT(ct.CM, c.Pair(ct.CS, p.B[h.slot-1])), c.ScaleT(prod, inv)), nil
}

// AlgebraPayloadBytes excludes policy/context, proofs, credentials, framing,
// parameters and downloads. It must not be reported as a full ciphertext size.
func (ct *Ciphertext) AlgebraPayloadBytes() int {
	return len(ct.CM.Bytes()) + len(ct.CS.Bytes()) + len(ct.CZ.Bytes()) + len(ct.DP.Bytes()) + len(ct.DC.Bytes()) + len(ct.DR.Bytes())
}
