package bench

import (
	"bytes"
	"math/big"
	"testing"

	"example.org/chare/internal/auth"
	"example.org/chare/internal/core"
)

// The upstream wrapper's small Type-A functional fixture. This is not a
// benchmark parameter choice or a numerical security recommendation.
const deliveryFunctionalParams = "type a\nq 4025338979\nh 6279780\nr 641\nexp2 9\nexp1 7\nsign1 1\nsign0 1\n"

func deliveryFixture(t *testing.T) (*core.Context, *core.Params, []*core.Root, []*core.UserSecret, *auth.Signer) {
	t.Helper()
	ctx, err := core.NewContext(deliveryFunctionalParams)
	if err != nil {
		t.Fatal(err)
	}
	pp, err := core.Setup(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	roots := make([]*core.Root, 3)
	secrets := make([]*core.UserSecret, 3)
	for i := range roots {
		roots[i], secrets[i], err = core.UserKeyGen(pp, i)
		if err != nil {
			t.Fatal(err)
		}
	}
	signer, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return ctx, pp, roots, secrets, signer
}

func deliveryClone(d *Delivery) *Delivery {
	return &Delivery{U: d.U, Payload: append([]byte(nil), d.Payload...), Precontext: append([]byte(nil), d.Precontext...), Signature: append([]byte(nil), d.Signature...)}
}

func TestScalarDeliveryCanonicalBoundaries(t *testing.T) {
	ctx, pp, roots, secrets, signer := deliveryFixture(t)
	metadata := auth.Frame("CHARE/test-immutable-row/v1", roots[0].Bytes(), []byte("version-1"))
	for _, delta := range []*big.Int{new(big.Int), new(big.Int).Sub(ctx.P, big.NewInt(1))} {
		d, err := SealScalar(ctx, pp.G, roots[0].Q, delta, metadata, signer)
		if err != nil {
			t.Fatal(err)
		}
		if d.U.Is0() {
			t.Fatal("delivery produced identity nonce point")
		}
		if !VerifyDelivery(d, signer.Public()) {
			t.Fatal("valid capsule signature rejected")
		}
		if err = ValidateDelivery(ctx, pp.G, roots[0].Q, d, metadata, signer.Public()); err != nil {
			t.Fatal(err)
		}
		got, err := OpenScalar(ctx, pp.G, secrets[0].Z, d, metadata, signer.Public())
		if err != nil || got.Cmp(delta) != 0 {
			t.Fatalf("canonical scalar did not round trip: %v", err)
		}
	}
	for _, invalid := range []*big.Int{big.NewInt(-1), new(big.Int).Set(ctx.P)} {
		if _, err := SealScalar(ctx, pp.G, roots[0].Q, invalid, metadata, signer); err == nil {
			t.Fatal("noncanonical plaintext accepted")
		}
	}
}

func TestScalarDeliveryBindsExpectedContextAndKey(t *testing.T) {
	ctx, pp, roots, secrets, signer := deliveryFixture(t)
	metadata := auth.Frame("CHARE/test-row/v1", roots[0].Bytes(), []byte("version-1"))
	d, err := SealScalar(ctx, pp.G, roots[0].Q, big.NewInt(23), metadata, signer)
	if err != nil {
		t.Fatal(err)
	}
	changedMetadata := auth.Frame("CHARE/test-row/v1", roots[0].Bytes(), []byte("version-2"))
	if !VerifyDelivery(d, signer.Public()) {
		t.Fatal("unchanged original signature should remain valid")
	}
	if err = ValidateDelivery(ctx, pp.G, roots[0].Q, d, changedMetadata, signer.Public()); err == nil {
		t.Fatal("a valid signature was accepted under the wrong record/version")
	}
	if _, err = OpenScalar(ctx, pp.G, secrets[0].Z, d, changedMetadata, signer.Public()); err == nil {
		t.Fatal("opening accepted the wrong immutable context")
	}
	// Choose a distinct NONZERO scalar deterministically; do not rely on two
	// small-field random recipient secrets happening to differ.
	wrongSecret := big.NewInt(1)
	if wrongSecret.Cmp(secrets[0].Z) == 0 {
		wrongSecret.SetInt64(2)
	}
	if _, err = OpenScalar(ctx, pp.G, wrongSecret, d, metadata, signer.Public()); err == nil {
		t.Fatal("opening accepted another reception binding")
	}
	before := DeliveryBytes(d)
	metadata[0] ^= 1
	if !bytes.Equal(before, DeliveryBytes(d)) {
		t.Fatal("caller metadata buffer aliases the capsule")
	}
}

func TestScalarDeliveryRejectsTampering(t *testing.T) {
	ctx, pp, roots, _, signer := deliveryFixture(t)
	metadata := []byte("complete-test-context")
	d, err := SealScalar(ctx, pp.G, roots[0].Q, big.NewInt(7), metadata, signer)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"payload", "context", "signature", "nonce"} {
		changed := deliveryClone(d)
		switch part {
		case "payload":
			changed.Payload[0] ^= 1
		case "context":
			changed.Precontext[0] ^= 1
		case "signature":
			changed.Signature[0] ^= 1
		case "nonce":
			changed.U = ctx.SourceAdd(d.U, pp.G)
		}
		if VerifyDelivery(changed, signer.Public()) {
			t.Fatalf("signature accepted tampered %s", part)
		}
	}
	if VerifyDelivery(nil, signer.Public()) || VerifyDelivery(&Delivery{}, signer.Public()) {
		t.Fatal("missing capsule accepted")
	}
}

func TestSignedNoncanonicalPayloadFailsOnlyAtOpening(t *testing.T) {
	ctx, pp, roots, secrets, signer := deliveryFixture(t)
	metadata := []byte("honest-format-malicious-payload-test")
	d, err := SealScalar(ctx, pp.G, roots[0].Q, big.NewInt(0), metadata, signer)
	if err != nil {
		t.Fatal(err)
	}
	// An authorized signer can deliberately encrypt the out-of-range integer p.
	// This tests framing/decoding, not the probability of breaking encryption.
	shared := ctx.SourceScale(d.U, secrets[0].Z)
	mask := scalarDeliveryMask(d.Precontext, shared.Bytes(), len(d.Payload))
	badInteger := ctx.P.FillBytes(make([]byte, len(d.Payload)))
	for i := range d.Payload {
		d.Payload[i] = badInteger[i] ^ mask[i]
	}
	d.Signature = signer.Sign(scalarSignatureMessage(d))
	if err = ValidateDelivery(ctx, pp.G, roots[0].Q, d, metadata, signer.Public()); err != nil {
		t.Fatalf("public validator incorrectly decides hidden scalar validity: %v", err)
	}
	if _, err = OpenScalar(ctx, pp.G, secrets[0].Z, d, metadata, signer.Public()); err == nil {
		t.Fatal("out-of-range decrypted scalar accepted")
	}
	// Local decode errors are not a public success-feedback oracle in this API.
}
