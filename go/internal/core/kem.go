package core

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/Nik-U/pbc"
)

type Literal struct {
	Basis    int
	Negative bool
}
type Target struct {
	Params     *Params
	P          *pbc.Element
	Context    []byte
	Version    uint64
	PreparedID [32]byte
	Weights    []*big.Int
	Policy     []Literal
	N          int
	cW         *big.Int
	coeff      []*big.Int
	members    map[int]int // immutable original cohort index
}
type Ciphertext struct {
	C0, C1     *pbc.Element
	Context    []byte
	Version    uint64
	PreparedID [32]byte
}

func PrepareTarget(a *Prepared, policy []Literal) (*Target, error) {
	return PrepareTargetWithContext(a, policy, nil)
}
func PrepareTargetWithContext(a *Prepared, policy []Literal, bind []byte) (*Target, error) {
	if a == nil {
		return nil, errors.New("nil aggregate")
	}
	weights := make([]*big.Int, len(policy))
	// Policy dimensions are fixed before any weight is sampled.
	for _, lit := range policy {
		if lit.Basis < 0 || lit.Basis >= a.Q {
			return nil, errors.New("unknown policy basis")
		}
	}
	for e := range weights {
		v, err := a.Params.Ctx.Sample(true)
		if err != nil {
			return nil, err
		}
		weights[e] = v
	}
	return targetWithWeights(a, policy, weights, bind)
}

// Deterministic weights are an unexported functional-test helper, not a normal
// encapsulation option. In particular production never fixes the first weight.
func targetWithWeights(a *Prepared, policy []Literal, weights []*big.Int, bind []byte) (*Target, error) {
	if a == nil || len(policy) != len(weights) {
		return nil, errors.New("invalid policy weights")
	}
	pp := a.Params
	c := pp.Ctx
	t := &Target{Params: pp, N: a.N, P: c.SourceAdd(pp.Y[pp.N-a.N], a.sums[0]), Version: a.Version, PreparedID: a.ID, Policy: append([]Literal(nil), policy...), Weights: make([]*big.Int, len(weights)), cW: new(big.Int), coeff: make([]*big.Int, a.Q), members: a.index}
	for b := range t.coeff {
		t.coeff[b] = new(big.Int)
	}
	fields := [][]byte{a.context, bind, a.ID[:], intBytes(a.Version), intBytes(uint64(len(policy)))}
	for e, lit := range policy {
		if lit.Basis < 0 || lit.Basis >= a.Q || weights[e] == nil || weights[e].Sign() <= 0 || weights[e].Cmp(c.P) >= 0 {
			return nil, errors.New("invalid policy or nonzero weight")
		}
		w := new(big.Int).Set(weights[e])
		t.Weights[e] = w
		sgn := byte(0)
		if lit.Negative {
			sgn = 1
			t.coeff[lit.Basis] = c.sub(t.coeff[lit.Basis], w)
		} else {
			t.cW = c.add(t.cW, w)
			t.coeff[lit.Basis] = c.add(t.coeff[lit.Basis], w)
		}
		wb, _ := c.ScalarBytes(w)
		fields = append(fields, intBytes(uint64(lit.Basis)), []byte{sgn}, wb)
	}
	t.P = c.SourceAdd(t.P, c.SourceScale(a.sumW, t.cW))
	for b, coef := range t.coeff {
		t.P = c.SourceAdd(t.P, c.SourceScale(a.sums[b+1], coef))
	}
	// This copies and binds the COMPLETE context. Metadata processing is real
	// work and is not hidden behind the two-element algebraic payload claim.
	t.Context = frame("CHARE-RATIONAL-CORE-v1/target", fields...)
	return t, nil
}

func Encapsulate(t *Target) (*Ciphertext, []byte, error) {
	if t == nil || t.Params == nil || t.P == nil {
		return nil, nil, errors.New("invalid target")
	}
	c := t.Params.Ctx
	s, err := c.Sample(false)
	if err != nil {
		return nil, nil, err
	}
	ct := &Ciphertext{C0: c.SourceScale(t.Params.G, s), C1: c.SourceScale(t.P, s), Context: append([]byte(nil), t.Context...), Version: t.Version, PreparedID: t.PreparedID}
	raw := c.TargetScale(t.Params.Z, s)
	return ct, deriveKey(ct, raw), nil
}
func deriveKey(ct *Ciphertext, raw *pbc.Element) []byte {
	b := frame("CHARE-RATIONAL-CORE-v1/H_K", ct.Context, ct.C0.Bytes(), ct.C1.Bytes(), raw.Bytes())
	sum := sha256.Sum256(b)
	return append([]byte(nil), sum[:]...)
}

// Decapsulate uses an externally validated/authenticated immutable HelpBundle.
// Call VerifyHelp against independently validated public sums at acquisition;
// retained old bundles remain tied to their old target version. This method
// performs local CPA decryption, not a hidden-qualification success oracle.
func Decapsulate(t *Target, ct *Ciphertext, user *UserSecret, deltas []*big.Int, h *HelpBundle) ([]byte, error) {
	if user == nil || t == nil || user.Params != t.Params || h == nil || user.Slot != h.Slot || user.V == nil || len(deltas) != len(t.coeff) {
		return nil, errors.New("wrong local user or mask dictionary")
	}
	c := t.Params.Ctx
	chi := c.mod(user.V)
	for b, d := range deltas {
		if d == nil || d.Sign() < 0 || d.Cmp(c.P) >= 0 {
			return nil, errors.New("missing or noncanonical local mask")
		}
		chi = c.add(chi, c.mul(t.coeff[b], d))
	}
	return DecapsulateWithCorrection(t, ct, chi, h)
}

// DecapsulateWithCorrection executes the real algebra for a caller-known
// correction. It does not recover a scalar of an opaque malicious root.
func DecapsulateWithCorrection(t *Target, ct *Ciphertext, chi *big.Int, h *HelpBundle) ([]byte, error) {
	if t == nil || ct == nil || h == nil || chi == nil || h.Params != t.Params || h.Version != t.Version || h.PreparedID != t.PreparedID || ct.Version != t.Version || ct.PreparedID != t.PreparedID || !bytes.Equal(ct.Context, t.Context) {
		return nil, errors.New("target/helper/ciphertext context mismatch")
	}
	if _, ok := t.members[h.Slot]; !ok {
		return nil, errors.New("slot not selected")
	}
	if ct.C0 == nil || ct.C1 == nil || h.R == nil || h.Gamma == nil || h.W == nil || len(h.Parts) != len(t.coeff)+1 {
		return nil, errors.New("incomplete ciphertext or help")
	}
	c := t.Params.Ctx
	if chi.Sign() < 0 || chi.Cmp(c.P) >= 0 {
		return nil, errors.New("noncanonical correction")
	}
	for _, x := range h.Parts {
		if x == nil {
			return nil, errors.New("missing help part")
		}
	}
	helper := c.SourceAdd(h.Parts[0], c.SourceScale(h.W, t.cW))
	for b, coef := range t.coeff {
		helper = c.SourceAdd(helper, c.SourceScale(h.Parts[b+1], coef))
	}
	inside := c.SourceAdd(c.SourceAdd(h.Gamma, helper), c.SourceScale(h.R, chi))
	raw := c.TargetDiv(c.Pair(ct.C0, inside), c.Pair(ct.C1, h.R))
	return deriveKey(ct, raw), nil
}

func (ct *Ciphertext) CoreBytes() int { return len(ct.C0.Bytes()) + len(ct.C1.Bytes()) }
func (ct *Ciphertext) Bytes() []byte {
	return frame("ciphertext", ct.PreparedID[:], intBytes(ct.Version), ct.Context, ct.C0.Bytes(), ct.C1.Bytes())
}
