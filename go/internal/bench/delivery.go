package bench

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/Nik-U/pbc"
	"example.org/chare/internal/auth"
	"example.org/chare/internal/core"
)

// Delivery is the actual source-DH scalar capsule used by the benchmark.
// All PBC objects are already typed, in-memory values from the same Context;
// this type is not an unchecked network decoder. Metadata must include the
// complete immutable system/root/row/version binding supplied by the caller.
type Delivery struct {
	U          *pbc.Element
	Payload    []byte
	Precontext []byte
	Signature  []byte
}

// SealScalar encrypts a canonical field scalar under Q=z*g with a nonzero
// delivery nonce. It signs the whole acyclic pre-context and ciphertext.
// SHA-256 with domain-separated counter blocks is the concrete implementation
// of the delivery mask; functional execution is not a proof of the ROM model.
func SealScalar(ctx *core.Context, g, Q *pbc.Element, delta *big.Int, metadata []byte, signer *auth.Signer) (*Delivery, error) {
	if ctx == nil || ctx.P == nil || ctx.Pairing == nil || g == nil || Q == nil || delta == nil || signer == nil {
		return nil, errors.New("delivery: missing context, key, scalar, or signer")
	}
	plain, err := ctx.ScalarBytes(delta)
	if err != nil {
		return nil, err
	}
	zero := ctx.SourceScale(g, big.NewInt(0))
	if g.Equals(zero) || Q.Equals(zero) {
		return nil, errors.New("delivery: identity base or reception key")
	}
	u, err := ctx.Sample(true)
	if err != nil {
		return nil, err
	}
	U := ctx.SourceScale(g, u)
	precontext := scalarPrecontext(ctx, g, Q, U, metadata, len(plain))
	// The oracle input is u*Q in the SOURCE group, not e(U,Q).
	shared := ctx.SourceScale(Q, u)
	mask := scalarDeliveryMask(precontext, shared.Bytes(), len(plain))
	payload := make([]byte, len(plain))
	for i := range plain {
		payload[i] = plain[i] ^ mask[i]
	}
	delivery := &Delivery{U: U, Payload: payload, Precontext: precontext}
	delivery.Signature = signer.Sign(scalarSignatureMessage(delivery))
	return delivery, nil
}

// OpenScalar verifies the complete capsule and exact expected immutable
// metadata, then computes z*U in the source group and rejects noncanonical
// decoded scalars. Signature validity alone is not currentness, semantic
// qualification, or a guarantee that a malicious issuer encrypted correctly.
func OpenScalar(ctx *core.Context, g *pbc.Element, receptionSecret *big.Int, delivery *Delivery, expectedMetadata []byte, public ed25519.PublicKey) (*big.Int, error) {
	if ctx == nil || ctx.P == nil || ctx.Pairing == nil || g == nil || receptionSecret == nil || delivery == nil || delivery.U == nil {
		return nil, errors.New("delivery: missing opening input")
	}
	if receptionSecret.Sign() == 0 {
		return nil, errors.New("delivery: zero reception secret")
	}
	if _, err := ctx.ScalarBytes(receptionSecret); err != nil {
		return nil, err
	}
	Q := ctx.SourceScale(g, receptionSecret)
	if err := ValidateDelivery(ctx, g, Q, delivery, expectedMetadata, public); err != nil {
		return nil, err
	}
	shared := ctx.SourceScale(delivery.U, receptionSecret)
	mask := scalarDeliveryMask(delivery.Precontext, shared.Bytes(), len(delivery.Payload))
	plain := make([]byte, len(delivery.Payload))
	for i := range plain {
		plain[i] = delivery.Payload[i] ^ mask[i]
	}
	return ctx.ParseScalar(plain)
}

// VerifyDelivery checks only the complete bitstring signature. It does not
// establish the expected row/recipient/version binding. A directory accepting
// a record must also reconstruct that binding, for example with ValidateDelivery.
func VerifyDelivery(delivery *Delivery, public ed25519.PublicKey) bool {
	return delivery != nil && delivery.U != nil && auth.Verify(public, scalarSignatureMessage(delivery), delivery.Signature)
}

// ValidateDelivery performs the public capsule checks without recovering delta
// or requiring a reception secret. It validates the exact expected metadata and
// reception key in addition to the signature. Current-version installation is
// a separate state-machine check; hidden payload correctness is not established.
func ValidateDelivery(ctx *core.Context, g, Q *pbc.Element, delivery *Delivery, expectedMetadata []byte, public ed25519.PublicKey) error {
	if ctx == nil || ctx.P == nil || ctx.Pairing == nil || g == nil || Q == nil || delivery == nil || delivery.U == nil {
		return errors.New("delivery: missing public validation input")
	}
	canonicalZero, err := ctx.ScalarBytes(big.NewInt(0))
	if err != nil {
		return err
	}
	if len(delivery.Payload) != len(canonicalZero) {
		return errors.New("delivery: wrong scalar payload length")
	}
	if !VerifyDelivery(delivery, public) {
		return errors.New("delivery: signature verification failed")
	}
	zero := ctx.SourceScale(g, big.NewInt(0))
	if g.Equals(zero) || Q.Equals(zero) || delivery.U.Equals(zero) {
		return errors.New("delivery: identity base, reception key, or nonce point")
	}
	expected := scalarPrecontext(ctx, g, Q, delivery.U, expectedMetadata, len(canonicalZero))
	if !bytes.Equal(expected, delivery.Precontext) {
		return errors.New("delivery: context or reception binding mismatch")
	}
	return nil
}

// DeliveryBytes reports the concrete framed transport bytes, including context
// and signature. The pre-context itself contains the nonce binding, so this
// deliberately explicit representation charges that repetition as transmitted.
// It returns nil for a missing capsule or nonce point.
func DeliveryBytes(delivery *Delivery) []byte {
	if delivery == nil || delivery.U == nil {
		return nil
	}
	return auth.Frame("CHARE/scalar-delivery/wire/v1", delivery.U.Bytes(), delivery.Precontext, delivery.Payload, delivery.Signature)
}

func scalarPrecontext(ctx *core.Context, g, Q, U *pbc.Element, metadata []byte, scalarLength int) []byte {
	return auth.Frame("CHARE/scalar-delivery/context/v1", ctx.P.Bytes(), g.Bytes(), Q.Bytes(), metadata, U.Bytes(), scalarDeliveryUint64(uint64(scalarLength)))
}

func scalarSignatureMessage(delivery *Delivery) []byte {
	return auth.Frame("CHARE/scalar-delivery/signature/v1", delivery.Precontext, delivery.U.Bytes(), delivery.Payload)
}

func scalarDeliveryMask(precontext, shared []byte, length int) []byte {
	out := make([]byte, 0, length)
	for counter := uint64(0); len(out) < length; counter++ {
		block := sha256.Sum256(auth.Frame("CHARE/scalar-delivery/mask/v1", precontext, shared, scalarDeliveryUint64(uint64(length)), scalarDeliveryUint64(counter)))
		take := length - len(out)
		if take > len(block) {
			take = len(block)
		}
		out = append(out, block[:take]...)
	}
	return out
}

func scalarDeliveryUint64(value uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, value)
	return buf
}
