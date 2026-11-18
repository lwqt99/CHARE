package core

import (
	"bytes"
	"math/big"
	"testing"
)

func TestSenderCopyPreservesTargetWithoutServerOrPrivateState(t *testing.T) {
	f := newFixture(t, 4)
	sender, err := f.agg.CopySender()
	if err != nil {
		t.Fatal(err)
	}
	if sender.public.roots != nil || sender.public.rows != nil || sender.public.total != nil ||
		sender.public.coeff != nil || sender.public.r != nil || sender.public.gamma != nil {
		t.Fatal("sender received server helper cache or complete record objects")
	}
	policy := []Literal{{Basis: 0}, {Basis: 1, Negative: true}}
	weights := []*big.Int{big.NewInt(2), big.NewInt(3)}
	left, err := targetWithWeights(f.agg, policy, weights, []byte("same authenticated bytes"))
	if err != nil {
		t.Fatal(err)
	}
	right, err := targetWithWeights(sender.public, policy, weights, []byte("same authenticated bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if !left.P.Equals(right.P) || !bytes.Equal(left.Context, right.Context) ||
		!bytes.Equal(sender.Bytes(), f.agg.SenderBytes()) {
		t.Fatal("copy changed algebra or complete KDF context")
	}
	ct, key, err := Encapsulate(right)
	if err != nil {
		t.Fatal(err)
	}
	h, err := Help(f.agg, 1) // slot 1 has A and lacks B
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decapsulate(right, ct, f.users[1], []*big.Int{f.deltas[0][1], f.deltas[1][1]}, h)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("sender copy could not encapsulate", err)
	}
}

func TestSenderCopyIsImmutableAndBindsAppendOnlyContext(t *testing.T) {
	f := newFixture(t, 4)
	sender, err := f.agg.CopySender()
	if err != nil {
		t.Fatal(err)
	}
	original := sender.Bytes()
	verifier := f.agg.VerifierBytes()
	// VerifierBytes alone does not cover this input to target preparation.
	f.agg.context = append(f.agg.context, []byte("extra history")...)
	if !bytes.Equal(verifier, f.agg.VerifierBytes()) || bytes.Equal(original, f.agg.SenderBytes()) {
		t.Fatal("test did not isolate unsigned history-context substitution")
	}
	f.agg.sums[0].Add(f.agg.sums[0], f.pp.G)
	f.agg.sumW.Add(f.agg.sumW, f.pp.G)
	f.agg.Slots[0] = 3
	f.agg.index[0] = 3
	f.agg.Version++
	if !bytes.Equal(original, sender.Bytes()) || sender.public.index[0] != 0 {
		t.Fatal("sender retained mutable directory aliases")
	}
	if _, err = sender.Prepare([]Literal{{Basis: 0}}, []byte("old snapshot")); err != nil {
		t.Fatal("independent old public sender state became unusable", err)
	}
}
