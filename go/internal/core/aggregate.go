package core

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/Nik-U/pbc"
)

// Prepared is a fixed cohort and dictionary. Rows are immutable copies.
// Its public mutation API changes one row; changing J requires Aggregate again.
type Prepared struct {
	Params   *Params
	N, Q     int // candidate count and dictionary positions, not setup capacity
	Slots    []int
	Version  uint64
	ID       [32]byte
	roots    []*Root
	rows     [][]*Row
	index    map[int]int
	sums     []*pbc.Element
	sumW     *pbc.Element
	total    [][]*pbc.Element
	coeff    [][]*big.Int
	r, gamma []*pbc.Element
	context  []byte
}

type HelpBundle struct {
	Params     *Params
	Slot       int
	Version    uint64
	PreparedID [32]byte
	R, Gamma   *pbc.Element
	Parts      []*pbc.Element // root basis, followed by each decision basis
	W          *pbc.Element
}

// Aggregate validates every complete array before preparing public caches.
func Aggregate(pp *Params, roots []*Root, rows [][]*Row) (*Prepared, error) {
	for _, r := range roots {
		if err := ValidateRoot(pp, r); err != nil {
			return nil, err
		}
	}
	for _, basis := range rows {
		if len(basis) != len(roots) {
			return nil, errors.New("dictionary dimension mismatch")
		}
		for j, row := range basis {
			if err := ValidateRow(pp, roots[j], row); err != nil {
				return nil, err
			}
		}
	}
	return AggregateValidated(pp, roots, rows)
}

// AggregateValidated separates the already measured full validation phase.
// Callers MUST first validate all full arrays. Shape/binding checks still run.
func AggregateValidated(pp *Params, roots []*Root, rows [][]*Row) (*Prepared, error) {
	if pp == nil || len(roots) == 0 || len(roots) > pp.N {
		return nil, errors.New("empty or oversized cohort")
	}
	n := len(roots)
	q := len(rows)
	c := pp.Ctx
	a := &Prepared{Params: pp, N: n, Q: q, Slots: make([]int, n), roots: make([]*Root, n), rows: make([][]*Row, q), index: make(map[int]int, n), sums: make([]*pbc.Element, q+1), sumW: c.SourceZero(), total: make([][]*pbc.Element, q+1), coeff: make([][]*big.Int, n), r: make([]*pbc.Element, n), gamma: make([]*pbc.Element, n)}
	fields := [][]byte{pp.Bytes(), intBytes(uint64(n)), intBytes(uint64(q))}
	for j, root := range roots {
		if err := rootShape(pp, root); err != nil {
			return nil, err
		}
		if _, ok := a.index[root.Slot]; ok {
			return nil, errors.New("duplicate slot")
		}
		a.roots[j] = cloneRoot(root)
		a.Slots[j] = root.Slot
		a.index[root.Slot] = j
		fields = append(fields, root.Bytes())
		a.sumW = c.SourceAdd(a.sumW, pp.W[root.Slot])
	}
	for b, basis := range rows {
		if len(basis) != n {
			return nil, errors.New("dictionary dimension mismatch")
		}
		a.rows[b] = make([]*Row, n)
		for j, row := range basis {
			if err := rowShape(pp, roots[j], row); err != nil {
				return nil, err
			}
			a.rows[b][j] = cloneRow(row)
			fields = append(fields, row.Bytes())
		}
	}
	a.context = frame("fixed-cohort-dictionary", fields...)
	a.ID = sha256.Sum256(a.context)
	for b := 0; b <= q; b++ {
		a.sums[b] = c.SourceZero()
		a.total[b] = make([]*pbc.Element, n)
		for r := range a.total[b] {
			a.total[b][r] = c.SourceZero()
		}
		for j := 0; j < n; j++ {
			x, proj := a.basis(b, j)
			a.sums[b] = c.SourceAdd(a.sums[b], x)
			mom := moments(pp, a.Slots[j], proj, n)
			for r := 0; r < n; r++ {
				a.total[b][r] = c.SourceAdd(a.total[b][r], mom[r])
			}
		}
	}
	poly := []*big.Int{big.NewInt(1)}
	for _, slot := range a.Slots {
		t := pp.Nodes[slot]
		next := make([]*big.Int, len(poly)+1)
		for k := range next {
			next[k] = new(big.Int)
		}
		for k, v := range poly {
			next[k] = c.sub(next[k], c.mul(t, v))
			next[k+1] = c.add(next[k+1], v)
		}
		poly = next
	}
	for j, slot := range a.Slots {
		l := make([]*big.Int, n)
		l[n-1] = new(big.Int).Set(poly[n])
		for k := n - 1; k >= 1; k-- {
			l[k-1] = c.add(poly[k], c.mul(pp.Nodes[slot], l[k]))
		}
		a.coeff[j] = l
		a.r[j] = c.SourceZero()
		a.gamma[j] = c.clone(pp.Gamma)
		for r := 0; r < n; r++ {
			a.r[j] = c.SourceAdd(a.r[j], c.SourceScale(pp.T[r], l[r]))
			if r < n-1 {
				a.gamma[j] = c.SourceAdd(a.gamma[j], c.SourceScale(pp.A[pp.N-n+r], l[r]))
			}
		}
	}
	return a, nil
}

func (a *Prepared) basis(b, j int) (*pbc.Element, []*pbc.Element) {
	if b == 0 {
		return a.roots[j].V, a.roots[j].Proj
	}
	return a.rows[b-1][j].E, a.rows[b-1][j].F
}
func moments(pp *Params, slot int, proj []*pbc.Element, n int) []*pbc.Element {
	m := make([]*pbc.Element, n)
	m[0] = pp.Ctx.SourceZero()
	for r := 0; r < n-1; r++ {
		m[r+1] = pp.Ctx.SourceAdd(proj[r], pp.Ctx.SourceScale(m[r], pp.Nodes[slot]))
	}
	return m
}

func Help(a *Prepared, slot int) (*HelpBundle, error) {
	if a == nil {
		return nil, errors.New("nil aggregate")
	}
	j, ok := a.index[slot]
	if !ok {
		return nil, errors.New("slot not selected")
	}
	pp := a.Params
	c := pp.Ctx
	h := &HelpBundle{Params: pp, Slot: slot, Version: a.Version, PreparedID: a.ID, R: c.clone(a.r[j]), Gamma: c.clone(a.gamma[j]), Parts: make([]*pbc.Element, a.Q+1), W: c.SourceZero()}
	for b := 0; b <= a.Q; b++ {
		_, proj := a.basis(b, j)
		own := moments(pp, slot, proj, a.N)
		h.Parts[b] = c.SourceZero()
		for r := 0; r < a.N; r++ {
			h.Parts[b] = c.SourceAdd(h.Parts[b], c.SourceScale(c.SourceSub(a.total[b][r], own[r]), a.coeff[j][r]))
		}
	}
	for r := 1; r < a.N; r++ {
		h.W = c.SourceAdd(h.W, c.SourceScale(pp.B[r-1], c.mul(big.NewInt(int64(r)), a.coeff[j][r])))
	}
	return h, nil
}

func VerifyHelp(a *Prepared, h *HelpBundle) error {
	if a == nil || h == nil || h.Params != a.Params || h.Version != a.Version || h.PreparedID != a.ID || len(h.Parts) != a.Q+1 {
		return errors.New("helper context mismatch")
	}
	j, ok := a.index[h.Slot]
	if !ok || h.R == nil || h.Gamma == nil || h.W == nil {
		return errors.New("invalid helper")
	}
	pp := a.Params
	c := pp.Ctx
	if !h.R.Equals(a.r[j]) {
		return errors.New("wrong public R")
	}
	if !c.Pair(pp.G, h.Gamma).Equals(c.TargetMul(pp.Z, c.Pair(pp.Y[pp.N-a.N], h.R))) {
		return errors.New("wrong Gamma helper")
	}
	for b := 0; b <= a.Q; b++ {
		if h.Parts[b] == nil {
			return errors.New("missing helper part")
		}
		x, _ := a.basis(b, j)
		if !c.Pair(pp.G, h.Parts[b]).Equals(c.Pair(c.SourceSub(a.sums[b], x), h.R)) {
			return errors.New("wrong basis helper")
		}
	}
	if !c.Pair(pp.G, h.W).Equals(c.Pair(c.SourceSub(a.sumW, pp.W[h.Slot]), h.R)) {
		return errors.New("wrong W helper")
	}
	return nil
}

// UpdateRow requires that the caller already ran ValidateRow on this new full
// array. Moment arithmetic is O(n); copying/hashing the capacity-length input
// and context bytes is charged separately and is not claimed to be O(n).
func (a *Prepared) UpdateRow(basis, slot int, row *Row) error {
	if a == nil || basis < 0 || basis >= a.Q {
		return errors.New("unknown dictionary basis")
	}
	j, ok := a.index[slot]
	if !ok {
		return errors.New("slot not selected")
	}
	if a.Version == ^uint64(0) {
		return errors.New("cache version overflow")
	}
	if err := rowShape(a.Params, a.roots[j], row); err != nil {
		return err
	}
	pp := a.Params
	c := pp.Ctx
	old := a.rows[basis][j]
	next := cloneRow(row)
	om := moments(pp, slot, old.F, a.N)
	nm := moments(pp, slot, next.F, a.N)
	b := basis + 1
	a.sums[b] = c.SourceAdd(a.sums[b], c.SourceSub(next.E, old.E))
	for r := 0; r < a.N; r++ {
		a.total[b][r] = c.SourceAdd(a.total[b][r], c.SourceSub(nm[r], om[r]))
	}
	a.rows[basis][j] = next
	a.Version++
	// A complete append-only update description, not only a digest, is retained.
	a.context = append(a.context, frame("row-update", intBytes(a.Version), intBytes(uint64(basis)), intBytes(uint64(slot)), next.Bytes())...)
	return nil
}
func (a *Prepared) ContextBytes() []byte { return append([]byte(nil), a.context...) }
func (h *HelpBundle) Bytes() []byte {
	return frame("help", h.PreparedID[:], intBytes(h.Version), intBytes(uint64(h.Slot)), h.R.Bytes(), h.Gamma.Bytes(), pointsBytes(h.Parts), h.W.Bytes())
}

// Bytes serializes the actual PUBLIC prepared state. The complete public
// context includes the original records and append-only updates, not secrets.
// This is a serialized-public-state metric, not a Go heap-memory estimate.
func (a *Prepared) Bytes() []byte {
	f := [][]byte{a.ID[:], intBytes(a.Version), intBytes(uint64(a.N)), intBytes(uint64(a.Q)), a.context, pointsBytes(a.sums), a.sumW.Bytes(), pointsBytes(a.r), pointsBytes(a.gamma)}
	for _, row := range a.total {
		f = append(f, pointsBytes(row))
	}
	for _, row := range a.coeff {
		var fields [][]byte
		for _, v := range row {
			b, _ := a.Params.Ctx.ScalarBytes(v)
			fields = append(fields, b)
		}
		f = append(f, frame("polynomial", fields...))
	}
	return frame("prepared-public-state", f...)
}

// VerifierBytes is the actual public material used by VerifyHelp, excluding
// the server's moment cache. A shared authenticated service must bind these
// values to the same immutable snapshot, or a client must recompute them from
// independently validated records. Signing only a raw-record manifest while
// giving unverified sums to VerifyHelp does not implement that trust boundary.
func (a *Prepared) VerifierBytes() []byte {
	f := [][]byte{a.Params.ID[:], a.ID[:], intBytes(a.Version), intBytes(uint64(a.N)), intBytes(uint64(a.Q)), pointsBytes(a.sums), a.sumW.Bytes(), pointsBytes(a.r)}
	for _, slot := range a.Slots {
		f = append(f, intBytes(uint64(slot)))
	}
	return frame("prepared-public-verifier", f...)
}
