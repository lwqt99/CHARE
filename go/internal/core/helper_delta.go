package core

import (
	"errors"
	"math/big"

	"github.com/Nik-U/pbc"
)

// HelpDelta stages a receiver's helper for one changed decision in the same
// frozen cohort. a and previous are the trusted, already validated old state;
// correctness of the old helper is a caller premise. No secret is consumed.
// The caller must authenticate next's complete immutable version/binding before
// calling, and atomically install this result only with that exact row update.
// All N-1 equations for next are checked here. a and previous are not mutated.
// A changed cohort or skipped update must use reconstruction (or sequentially
// replay each authenticated update), not relabel the old helper.
func HelpDelta(a *Prepared, previous *HelpBundle, basis, changedSlot int, next *Row) (*HelpBundle, error) {
	if a == nil || previous == nil || previous.Params != a.Params ||
		previous.PreparedID != a.ID || previous.Version != a.Version ||
		a.Version == ^uint64(0) || basis < 0 || basis >= a.Q || len(previous.Parts) != a.Q+1 {
		return nil, errors.New("helper delta: incompatible old state")
	}
	i, ok := a.index[previous.Slot]
	j, selected := a.index[changedSlot]
	if !ok || !selected || previous.R == nil || previous.Gamma == nil || previous.W == nil {
		return nil, errors.New("helper delta: slot or helper shape")
	}
	for _, point := range previous.Parts {
		if point == nil {
			return nil, errors.New("helper delta: missing old part")
		}
	}
	if err := ValidateRow(a.Params, a.roots[j], next); err != nil {
		return nil, err
	}
	c := a.Params.Ctx
	out := &HelpBundle{Params: a.Params, Slot: previous.Slot, Version: previous.Version + 1,
		PreparedID: previous.PreparedID, R: c.clone(previous.R), Gamma: c.clone(previous.Gamma),
		W: c.clone(previous.W), Parts: make([]*pbc.Element, len(previous.Parts))}
	for k, point := range previous.Parts {
		out.Parts[k] = c.clone(point)
	}
	if i == j {
		return out, nil
	}
	// q_i(X)/(X-t_j) has degree n-2. These are known field coefficients;
	// the division never divides by an unknown setup scalar or group element.
	co := make([]*big.Int, a.N-1)
	co[a.N-2] = new(big.Int).Set(a.coeff[i][a.N-1])
	for k := a.N - 2; k > 0; k-- {
		co[k-1] = c.add(a.coeff[i][k], c.mul(a.Params.Nodes[changedSlot], co[k]))
	}
	if c.add(a.coeff[i][0], c.mul(a.Params.Nodes[changedSlot], co[0])).Sign() != 0 {
		return nil, errors.New("helper delta: changed node is not an off-slot root")
	}
	delta := c.SourceZero()
	for k, weight := range co {
		delta = c.SourceAdd(delta, c.SourceScale(c.SourceSub(next.F[k], a.rows[basis][j].F[k]), weight))
	}
	out.Parts[basis+1] = c.SourceAdd(out.Parts[basis+1], delta)
	return out, nil
}
