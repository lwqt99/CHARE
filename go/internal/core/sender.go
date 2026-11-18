package core

import (
	"errors"

	"github.com/Nik-U/pbc"
)

// SenderState is an immutable copy of the public material used to prepare a
// target. It contains no receiver secrets, roots, rows, or server moment cache.
// Params is shared as immutable system setup. This is a typed-object adapter,
// not a decoder for untrusted network encodings.
type SenderState struct{ public *Prepared }

// SenderBytes binds all inputs consumed by target preparation, including its
// complete append-only context. Authenticating only VerifierBytes omits this
// context, which target preparation also hashes into the session key.
func (a *Prepared) SenderBytes() []byte {
	f := [][]byte{a.Params.ID[:], a.ID[:], intBytes(a.Version), intBytes(uint64(a.N)),
		intBytes(uint64(a.Q)), a.context, pointsBytes(a.sums), a.sumW.Bytes()}
	for _, slot := range a.Slots {
		f = append(f, intBytes(uint64(slot)))
	}
	return frame("CHARE/public-sender-state/v1", f...)
}

// CopySender performs real point and context copies. Its result must be bound
// to a pinned authority's authenticated snapshot before use by an application.
func (a *Prepared) CopySender() (*SenderState, error) {
	if a == nil || a.Params == nil || a.N < 1 || a.N > a.Params.N ||
		len(a.Slots) != a.N || len(a.sums) != a.Q+1 || a.sumW == nil {
		return nil, errors.New("incomplete public sender material")
	}
	c := a.Params.Ctx
	p := &Prepared{Params: a.Params, N: a.N, Q: a.Q, Version: a.Version, ID: a.ID,
		Slots: append([]int(nil), a.Slots...), context: append([]byte(nil), a.context...),
		index: make(map[int]int, a.N), sums: make([]*pbc.Element, len(a.sums)), sumW: c.clone(a.sumW)}
	for j, slot := range p.Slots {
		if slot < 0 || slot >= a.Params.N {
			return nil, errors.New("invalid sender slot")
		}
		if _, exists := p.index[slot]; exists {
			return nil, errors.New("duplicate sender slot")
		}
		p.index[slot] = j
	}
	for j, point := range a.sums {
		if point == nil {
			return nil, errors.New("missing sender coefficient")
		}
		p.sums[j] = c.clone(point)
	}
	return &SenderState{public: p}, nil
}

func (s *SenderState) Bytes() []byte { return s.public.SenderBytes() }

func (s *SenderState) Prepare(policy []Literal, context []byte) (*Target, error) {
	if s == nil || s.public == nil {
		return nil, errors.New("no authenticated sender state")
	}
	return PrepareTargetWithContext(s.public, policy, context)
}
