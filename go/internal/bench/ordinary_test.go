package bench

import (
	"bytes"
	"testing"

	"example.org/chare/internal/core"
)

func TestOrdinaryAnchorAndEveryListedRecipient(t *testing.T) {
	ctx, pp, roots, secrets, _ := deliveryFixture(t)
	context := []byte("authorized-list-snapshot")
	for _, indices := range [][]int{{1}, {2, 0}, {0, 1, 2}} {
		selected := make([]*core.Root, len(indices))
		for j, i := range indices {
			selected[j] = roots[i]
		}
		ct, key, err := OrdinaryEnc(ctx, pp.G, selected, context)
		if err != nil {
			t.Fatal(err)
		}
		if ct.Anchor != 0 || len(ct.Wraps) != len(selected)-1 {
			t.Fatal("anchored KEM did not use exactly n-1 wraps")
		}
		for j, i := range indices {
			if ct.RecipientIDs[j] != i {
				t.Fatal("recipient order was changed")
			}
			got, err := OrdinaryDec(ctx, ct, secrets[i], context)
			if err != nil || !bytes.Equal(got, key) {
				t.Fatalf("listed recipient %d failed: %v", i, err)
			}
		}
		if len(OrdinaryBytes(ct)) <= len(ct.Head.Bytes())+32*len(ct.Wraps) {
			t.Fatal("wire accounting omitted list/context framing")
		}
	}
}

func TestOrdinaryListAndContextValidation(t *testing.T) {
	ctx, pp, roots, secrets, _ := deliveryFixture(t)
	context := []byte("snapshot-A")
	if _, _, err := OrdinaryEnc(ctx, pp.G, nil, context); err == nil {
		t.Fatal("empty list has no anchor")
	}
	if _, _, err := OrdinaryEnc(ctx, pp.G, []*core.Root{roots[0], roots[0]}, context); err == nil {
		t.Fatal("duplicate recipient accepted")
	}
	ct, _, err := OrdinaryEnc(ctx, pp.G, roots[:2], context)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OrdinaryDec(ctx, ct, secrets[2], context); err == nil {
		t.Fatal("unlisted slot accepted by the list interface")
	}
	if _, err = OrdinaryDec(ctx, ct, secrets[0], []byte("snapshot-B")); err == nil {
		t.Fatal("wrong expected context accepted")
	}
	before := OrdinaryBytes(ct)
	context[0] ^= 1
	if !bytes.Equal(before, OrdinaryBytes(ct)) {
		t.Fatal("caller context buffer aliases ciphertext")
	}
	// These are structural rejection tests, not a probabilistic security test.
	ct.Anchor = 1
	if _, err = OrdinaryDec(ctx, ct, secrets[0], ct.Context); err == nil {
		t.Fatal("unsupported anchor framing accepted")
	}
	ct.Anchor = 0
	ct.Wraps[0] = ct.Wraps[0][:31]
	if _, err = OrdinaryDec(ctx, ct, secrets[1], ct.Context); err == nil {
		t.Fatal("wrong wrap length accepted")
	}
}
