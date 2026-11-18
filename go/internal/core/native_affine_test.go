package core

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"os"
	"testing"
)

// Diagnostic over the original PBC backend and native KDF. The fixture
// explicitly releases one holder-generated point and one issuer mask.
func TestRetainedAffinePointAndNativeContext(t *testing.T) {
	path := os.Getenv("CHARE_REPLAY_PARAMS")
	if path == "" {
		t.Skip("set CHARE_REPLAY_PARAMS to the archived Type-A parameter file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewContext(string(data))
	if err != nil {
		t.Fatal(err)
	}
	pp, err := Setup(c, 4)
	if err != nil {
		t.Fatal(err)
	}
	first, holder, err := UserKeyGen(pp, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := UserKeyGen(pp, 1)
	if err != nil {
		t.Fatal(err)
	}
	allow, openedMask, err := Issue(pp, first, true)
	if err != nil {
		t.Fatal(err)
	}
	deny, _, err := Issue(pp, second, false)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := Aggregate(pp, []*Root{first, second}, [][]*Row{{allow, deny}})
	if err != nil {
		t.Fatal(err)
	}
	target, err := PrepareTargetWithContext(prepared, []Literal{{Basis: 0}}, []byte("retained-affine"))
	if err != nil {
		t.Fatal(err)
	}
	ct, originalKey, err := Encapsulate(target)
	if err != nil {
		t.Fatal(err)
	}
	originalBytes := append([]byte(nil), ct.Bytes()...)
	help, err := Help(prepared, first.Slot)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyHelp(prepared, help); err != nil {
		t.Fatal(err)
	}
	weight := target.Weights[0]

	// Compute the expected target independently using the original recipient's
	// validated helper and decoding inputs. The public replay below omits them.
	chi := c.add(holder.V, c.mul(weight, openedMask))
	helper := c.SourceAdd(help.Parts[0], c.SourceScale(c.SourceAdd(help.W, help.Parts[1]), weight))
	inside := c.SourceAdd(c.SourceAdd(help.Gamma, helper), c.SourceScale(help.R, chi))
	expectedGT := c.TargetDiv(c.Pair(ct.C0, inside), c.Pair(ct.C1, help.R))
	if !bytes.Equal(deriveKey(ct, expectedGT), originalKey) {
		t.Fatal("original recipient and encapsulator disagree")
	}
	if expectedGT.Is1() {
		t.Skip("identity encapsulation input from a full-field test sample")
	}

	// The holder produces the disclosed point; the replay uses its handle and
	// known offset, never its secret scalar. The refused slot has x_2=0.
	offset := big.NewInt(17)
	point := c.SourceScale(pp.H, c.add(holder.V, offset))
	q0 := pp.Nodes[second.Slot]
	x1 := c.sub(q0, pp.Nodes[first.Slot])
	qPoint := c.SourceSub(c.SourceScale(pp.T[0], q0), pp.T[1])
	base := c.SourceSub(pp.Gamma, c.SourceScale(pp.A[pp.N-2], q0))
	base = c.SourceAdd(base, c.SourceAdd(first.Proj[0], c.SourceScale(c.SourceAdd(pp.B[0], allow.F[0]), weight)))
	base = c.SourceAdd(base, c.SourceAdd(second.Proj[0], c.SourceScale(c.SourceAdd(pp.B[0], deny.F[0]), weight)))
	affine := c.sub(c.mul(weight, openedMask), offset)
	if affine.Sign() == 0 {
		t.Skip("zero affine correction from a full-field test sample")
	}
	correction := c.SourceScale(c.SourceAdd(point, c.SourceScale(pp.H, affine)), x1)
	actualGT := c.TargetMul(c.Pair(ct.C0, c.SourceSub(base, correction)), c.Pair(ct.C1, qPoint))
	if !bytes.Equal(actualGT.Bytes(), expectedGT.Bytes()) || !bytes.Equal(deriveKey(ct, actualGT), originalKey) {
		t.Fatal("affine replay disagrees with the original GT or KDF")
	}
	withoutAffine := c.SourceScale(point, x1)
	missing := c.TargetMul(c.Pair(ct.C0, c.SourceSub(base, withoutAffine)), c.Pair(ct.C1, qPoint))
	if bytes.Equal(missing.Bytes(), expectedGT.Bytes()) {
		t.Fatal("missing affine correction yielded the original target input")
	}
	wrong := *ct
	wrong.Context = append(append([]byte(nil), ct.Context...), 0)
	if bytes.Equal(deriveKey(&wrong, actualGT), originalKey) || !bytes.Equal(ct.Bytes(), originalBytes) {
		t.Fatal("context binding or original ciphertext preservation failed")
	}
	t.Logf("params_sha256=%x ciphertext_sha256=%x context_sha256=%x gt_sha256=%x key_sha256=%x",
		sha256.Sum256(data), sha256.Sum256(originalBytes), sha256.Sum256(ct.Context),
		sha256.Sum256(actualGT.Bytes()), sha256.Sum256(originalKey))
}
