package core

import (
	"math/big"
	"testing"

	"example.org/chare/internal/ledger"
)

func TestLedgerFactFailureWitnessInActualPBC(t *testing.T) {
	f := newFixture(t, 4)
	c := f.pp.Ctx
	i := 1
	zeroPoly := make(ledger.Vector, f.pp.N)
	for k := range zeroPoly {
		zeroPoly[k] = new(big.Int)
	}
	p := make(ledger.Vector, f.pp.N)
	for k := range p {
		p[k] = new(big.Int)
	}
	p[0] = c.sub(new(big.Int), f.pp.Nodes[i])
	p[1].SetInt64(1)
	minusOne := c.sub(new(big.Int), big.NewInt(1))
	a, err := ledger.New(ledger.Input{Modulus: c.P, Nodes: f.pp.Nodes, Slots: []int{i}, PadCount: 1,
		Points: []ledger.Point{{Polynomial: ledger.Matrix{p}, Pads: ledger.Vector{big.NewInt(1)}},
			{Polynomial: ledger.Matrix{zeroPoly}, Pads: ledger.Vector{minusOne}}}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := a.Facts(ledger.Vector{big.NewInt(1)})
	if err != nil || r.Compatible || r.Failure.Kind != "polynomial" {
		t.Fatal("missing coefficient witness", err)
	}
	if len(a.Capability()) != 0 {
		t.Fatal("unexpected residue capability")
	}
	left := r.Failure.Left
	for _, w := range []int64{0, 9} {
		for _, pad := range []int64{0, 11} {
			for _, fact := range []bool{false, true} {
				row := issueWithDelta(f.pp, f.roots[i], fact, big.NewInt(w))
				base := c.SourceSub(f.pp.T[1], c.SourceScale(f.pp.T[0], f.pp.Nodes[i]))
				c1 := c.SourceAdd(c.SourceScale(base, big.NewInt(w)), c.SourceScale(f.pp.H, big.NewInt(pad)))
				c2 := c.SourceNeg(c.SourceScale(f.pp.H, big.NewInt(pad)))
				combined := c.SourceAdd(c.SourceScale(c1, left[0]), c.SourceScale(c2, left[1]))
				diff := c.SourceSub(combined, c.SourceScale(row.F[0], left[0]))
				expect := c.SourceZero()
				if fact {
					expect = c.SourceScale(f.pp.B[0], left[0])
				}
				if !diff.Equals(expect) {
					t.Fatal("dual witness failed actual group identity")
				}
				if !fact && !diff.Is0() {
					t.Fatal("zero fact distinguished incorrectly")
				}
				if fact && diff.Is0() {
					t.Fatal("nonzero fact lost")
				}
			}
		}
	}
}
