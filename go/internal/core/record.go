package core

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/Nik-U/pbc"
)

type Root struct {
	Params *Params
	Slot   int
	V, Q   *pbc.Element
	Proj   []*pbc.Element
}
type UserSecret struct {
	Params *Params
	Slot   int
	V, Z   *big.Int
}
type Row struct {
	Params      *Params
	Slot        int
	E           *pbc.Element
	F           []*pbc.Element
	RootBinding []byte
}

func (r *Root) Bytes() []byte {
	return frame("root", r.Params.ID[:], intBytes(uint64(r.Slot)), r.V.Bytes(), r.Q.Bytes(), pointsBytes(r.Proj))
}
func (r *Row) Bytes() []byte {
	return frame("decision-row", r.Params.ID[:], intBytes(uint64(r.Slot)), r.RootBinding, r.E.Bytes(), pointsBytes(r.F))
}

func UserKeyGen(pp *Params, slot int) (*Root, *UserSecret, error) {
	if pp == nil || slot < 0 || slot >= pp.N {
		return nil, nil, errors.New("slot out of range")
	}
	c := pp.Ctx
	v, err := c.Sample(false)
	if err != nil {
		return nil, nil, err
	}
	z, err := c.Sample(true)
	if err != nil {
		return nil, nil, err
	}
	r := &Root{Params: pp, Slot: slot, V: c.SourceScale(pp.G, v), Q: c.SourceScale(pp.G, z), Proj: make([]*pbc.Element, pp.N-1)}
	for k := range r.Proj {
		r.Proj[k] = c.SourceScale(c.SourceSub(pp.T[k+1], c.SourceScale(pp.T[k], pp.Nodes[slot])), v)
	}
	return r, &UserSecret{Params: pp, Slot: slot, V: v, Z: z}, nil
}

// Issue is the algebraic honest-issuer step. The returned delta is PRIVATE;
// the delivery/authentication layer must deliver it to this root's holder.
func Issue(pp *Params, root *Root, y bool) (*Row, *big.Int, error) {
	if err := rootShape(pp, root); err != nil {
		return nil, nil, err
	}
	delta, err := pp.Ctx.Sample(false)
	if err != nil {
		return nil, nil, err
	}
	return issueWithDelta(pp, root, y, delta), delta, nil
}
func issueWithDelta(pp *Params, root *Root, y bool, delta *big.Int) *Row {
	c := pp.Ctx
	i := root.Slot
	r := &Row{Params: pp, Slot: i, E: c.SourceScale(pp.G, delta), F: make([]*pbc.Element, pp.N-1), RootBinding: append([]byte(nil), root.Bytes()...)}
	if y {
		r.E = c.SourceSub(r.E, pp.W[i])
	}
	for k := range r.F {
		r.F[k] = c.SourceScale(c.SourceSub(pp.T[k+1], c.SourceScale(pp.T[k], pp.Nodes[i])), delta)
		if y {
			r.F[k] = c.SourceSub(r.F[k], pp.B[k])
		}
	}
	return r
}
func rootShape(pp *Params, r *Root) (err error) {
	defer func() {
		if problem := recover(); problem != nil {
			err = fmt.Errorf("invalid typed root element: %v", problem)
		}
	}()
	if pp == nil || r == nil || r.Params != pp || r.Slot < 0 || r.Slot >= pp.N || r.V == nil || r.Q == nil || len(r.Proj) != pp.N-1 {
		return errors.New("invalid root parameters or shape")
	}
	if r.V.Pairing() != pp.Ctx.Pairing || r.Q.Pairing() != pp.Ctx.Pairing {
		return errors.New("foreign root pairing")
	}
	// Set performs the backend's checked source-field match for Q, which is
	// otherwise not part of the projection equations. This is not a wire parser.
	_ = pp.Ctx.clone(r.Q)
	if r.Q.Is0() {
		return errors.New("identity reception key")
	}
	for _, v := range r.Proj {
		if v == nil || v.Pairing() != pp.Ctx.Pairing {
			return errors.New("missing root projection")
		}
	}
	return nil
}
func rowShape(pp *Params, root *Root, row *Row) error {
	if err := rootShape(pp, root); err != nil {
		return err
	}
	if row == nil || row.Params != pp || row.Slot != root.Slot || row.E == nil || len(row.F) != pp.N-1 || !bytes.Equal(row.RootBinding, root.Bytes()) {
		return errors.New("invalid row shape or root binding")
	}
	for _, v := range row.F {
		if v == nil || v.Pairing() != pp.Ctx.Pairing {
			return errors.New("missing row projection")
		}
	}
	return nil
}
func ValidateRoot(pp *Params, r *Root) error {
	if err := rootShape(pp, r); err != nil {
		return err
	}
	return validateProjection(pp, r.Slot, r.V, r.Proj)
}
func ValidateRow(pp *Params, root *Root, row *Row) error {
	if err := rowShape(pp, root, row); err != nil {
		return err
	}
	return validateProjection(pp, row.Slot, row.E, row.F)
}
func validateProjection(pp *Params, slot int, x *pbc.Element, xs []*pbc.Element) (err error) {
	defer func() {
		if problem := recover(); problem != nil {
			err = fmt.Errorf("invalid typed projection input: %v", problem)
		}
	}()
	if x.Pairing() != pp.Ctx.Pairing {
		return errors.New("foreign projection pairing")
	}
	c := pp.Ctx
	for k := 0; k < pp.N-1; k++ {
		base := c.SourceSub(pp.T[k+1], c.SourceScale(pp.T[k], pp.Nodes[slot]))
		if !c.Pair(x, base).Equals(c.Pair(pp.G, xs[k])) {
			return errors.New("projection equation failed")
		}
	}
	return nil
}
func cloneRoot(r *Root) *Root {
	c := r.Params.Ctx
	s := &Root{Params: r.Params, Slot: r.Slot, V: c.clone(r.V), Q: c.clone(r.Q), Proj: make([]*pbc.Element, len(r.Proj))}
	for k, x := range r.Proj {
		s.Proj[k] = c.clone(x)
	}
	return s
}
func cloneRow(r *Row) *Row {
	c := r.Params.Ctx
	s := &Row{Params: r.Params, Slot: r.Slot, E: c.clone(r.E), F: make([]*pbc.Element, len(r.F)), RootBinding: append([]byte(nil), r.RootBinding...)}
	for k, x := range r.F {
		s.F[k] = c.clone(x)
	}
	return s
}
