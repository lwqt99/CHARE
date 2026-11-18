package bench

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/Nik-U/pbc"
	"example.org/chare/internal/auth"
	"example.org/chare/internal/core"
)

// OrdinaryCipher is a shared-head source-DH anchored KEM. Its recipient list is
// explicitly public. This is a data-plane baseline for an authorized list, not
// a hidden-qualification registered-encryption implementation.
// The first listed recipient is the anchor; Wraps has n-1 entries in list order.
type OrdinaryCipher struct {
	Head         *pbc.Element
	Anchor       int
	RecipientIDs []int
	Wraps        [][]byte
	Context      []byte
}

// OrdinaryEnc samples a full-domain ephemeral scalar, publishes one source
// head, and uses the first recipient's derived 32-byte key as the common key.
// Every subsequent recipient receives one XOR wrap. A full-domain zero sample
// is retained, consistently with the core; no concrete security claim follows.
func OrdinaryEnc(ctx *core.Context, g *pbc.Element, recipients []*core.Root, context []byte) (*OrdinaryCipher, []byte, error) {
	if ctx == nil || ctx.P == nil || ctx.Pairing == nil || g == nil || len(recipients) == 0 {
		return nil, nil, errors.New("ordinary: missing context, base, or recipients")
	}
	zero := ctx.SourceScale(g, big.NewInt(0))
	if g.Equals(zero) {
		return nil, nil, errors.New("ordinary: identity base")
	}
	ids := make([]int, len(recipients))
	seen := make(map[int]bool, len(recipients))
	for i, root := range recipients {
		if root == nil || root.Params == nil || root.Params.Ctx != ctx || root.Q == nil || root.Slot < 0 || root.Slot >= root.Params.N {
			return nil, nil, errors.New("ordinary: invalid recipient or foreign context")
		}
		if !root.Params.G.Equals(g) || root.Q.Equals(zero) || seen[root.Slot] {
			return nil, nil, errors.New("ordinary: base mismatch, identity key, or duplicate recipient")
		}
		seen[root.Slot] = true
		ids[i] = root.Slot
	}
	s, err := ctx.Sample(false)
	if err != nil {
		return nil, nil, err
	}
	ct := &OrdinaryCipher{
		Head: ctx.SourceScale(g, s), Anchor: 0, RecipientIDs: ids,
		Wraps: make([][]byte, len(recipients)-1), Context: append([]byte(nil), context...),
	}
	header := ordinaryHeader(ctx, g, ct)
	var common []byte
	for i, root := range recipients {
		shared := ctx.SourceScale(root.Q, s)
		key := ordinaryRecipientKey(header, root.Slot, root.Q, shared)
		if i == 0 {
			common = key
			continue
		}
		wrap := make([]byte, sha256.Size)
		for j := range wrap {
			wrap[j] = common[j] ^ key[j]
		}
		ct.Wraps[i-1] = wrap
	}
	return ct, common, nil
}

// OrdinaryDec uses only the recipient's own reception secret and the public
// framed ciphertext. It binds the expected immutable context. This CPA baseline
// does not claim to authenticate a malicious ciphertext or enforce currentness.
func OrdinaryDec(ctx *core.Context, ct *OrdinaryCipher, secret *core.UserSecret, context []byte) ([]byte, error) {
	if ctx == nil || ctx.P == nil || ctx.Pairing == nil || ct == nil || ct.Head == nil || secret == nil || secret.Params == nil || secret.Params.Ctx != ctx || secret.Params.G == nil || secret.Z == nil {
		return nil, errors.New("ordinary: missing or foreign decryption input")
	}
	if len(ct.RecipientIDs) == 0 || ct.Anchor != 0 || len(ct.Wraps) != len(ct.RecipientIDs)-1 || !bytes.Equal(ct.Context, context) {
		return nil, errors.New("ordinary: malformed header or context mismatch")
	}
	if secret.Z.Sign() == 0 {
		return nil, errors.New("ordinary: zero reception secret")
	}
	if _, err := ctx.ScalarBytes(secret.Z); err != nil {
		return nil, err
	}
	seen := make(map[int]bool, len(ct.RecipientIDs))
	index := -1
	for i, id := range ct.RecipientIDs {
		if id < 0 || id >= secret.Params.N || seen[id] {
			return nil, errors.New("ordinary: invalid or duplicate recipient identifier")
		}
		seen[id] = true
		if id == secret.Slot {
			index = i
		}
	}
	for _, wrap := range ct.Wraps {
		if len(wrap) != sha256.Size {
			return nil, errors.New("ordinary: wrong wrap length")
		}
	}
	if index < 0 {
		return nil, errors.New("ordinary: recipient is not listed")
	}
	g := secret.Params.G
	Q := ctx.SourceScale(g, secret.Z)
	shared := ctx.SourceScale(ct.Head, secret.Z)
	key := ordinaryRecipientKey(ordinaryHeader(ctx, g, ct), secret.Slot, Q, shared)
	if index == 0 {
		return key, nil
	}
	for i := range key {
		key[i] ^= ct.Wraps[index-1][i]
	}
	return key, nil
}

// OrdinaryBytes counts the actual wire framing, including the explicit public
// recipient list, anchor, wraps and immutable context. Common parameter and
// reception-key acquisition are separate setup/registry costs.
func OrdinaryBytes(ct *OrdinaryCipher) []byte {
	if ct == nil || ct.Head == nil {
		return nil
	}
	return auth.Frame("CHARE/ordinary-dh/ciphertext/v1", ct.Context, ct.Head.Bytes(), ordinaryIndexField(ct.Anchor), ordinaryRecipientList(ct.RecipientIDs), auth.Frame("CHARE/ordinary-dh/wraps/v1", ct.Wraps...))
}

func ordinaryHeader(ctx *core.Context, g *pbc.Element, ct *OrdinaryCipher) []byte {
	return auth.Frame("CHARE/ordinary-dh/header/v1", ctx.P.Bytes(), g.Bytes(), ct.Context, ct.Head.Bytes(), ordinaryIndexField(ct.Anchor), ordinaryRecipientList(ct.RecipientIDs))
}

func ordinaryRecipientKey(header []byte, id int, public, shared *pbc.Element) []byte {
	key := sha256.Sum256(auth.Frame("CHARE/ordinary-dh/recipient-key/v1", header, ordinaryIndexField(id), public.Bytes(), shared.Bytes()))
	return append([]byte(nil), key[:]...)
}

func ordinaryRecipientList(ids []int) []byte {
	fields := make([][]byte, len(ids))
	for i, id := range ids {
		fields[i] = ordinaryIndexField(id)
	}
	return auth.Frame("CHARE/ordinary-dh/recipient-list/v1", fields...)
}

func ordinaryIndexField(value int) []byte {
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, uint64(value))
	return encoded
}
