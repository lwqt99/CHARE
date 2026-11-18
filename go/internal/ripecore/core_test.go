package ripecore

import (
	_ "embed"
	"errors"
	"math/big"
	"testing"
)

// Upstream PBC 0.5.14 param/f.param, retained verbatim as a trusted functional
// fixture. Its field sizes do not certify a concrete security level.
//
//go:embed testdata/f.param
var functionalF string

func testContext(t *testing.T) *Context {
	t.Helper()
	c, err := NewTrustedContext(functionalF)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func fixedCoins(n, m int) setupCoins {
	s := setupCoins{alpha: big.NewInt(2), beta: big.NewInt(3), gamma: big.NewInt(5), t: make([]*big.Int, n), u: make([][]*big.Int, m+5), dummy: make([]*big.Int, m+5)}
	for i := range s.t {
		s.t[i] = big.NewInt(int64(i + 2))
	}
	for w := range s.u {
		s.u[w] = make([]*big.Int, n+1)
		for i := range s.u[w] {
			s.u[w][i] = big.NewInt(int64(10*w + i + 2))
		}
		s.dummy[w] = big.NewInt(0)
	}
	s.dummy[0] = big.NewInt(1)
	return s
}

type fixture struct {
	p        *Parameters
	keys     []*RawKey
	secrets  []*KeySecret
	rows     [][]*Increment
	masks    [][]*IncrementSecret
	active   [][]bool
	prepared *Prepared
}

func fourClasses(t *testing.T) *fixture {
	t.Helper()
	c := testContext(t)
	p, err := setupWithCoins(c, 4, 2, fixedCoins(4, 2))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{p: p, keys: make([]*RawKey, 4), secrets: make([]*KeySecret, 4), rows: make([][]*Increment, 4), masks: make([][]*IncrementSecret, 4), active: make([][]bool, 4)}
	for i := 0; i < 4; i++ {
		f.keys[i], f.secrets[i], err = rawKey(p, i+1, big.NewInt(int64(i+7)))
		if err != nil {
			t.Fatal(err)
		}
		f.rows[i] = make([]*Increment, 2)
		f.masks[i] = make([]*IncrementSecret, 2)
		f.active[i] = []bool{true, true}
		for a := 0; a < 2; a++ {
			f.rows[i][a], f.masks[i][a], err = increment(p, i+1, a, (i>>a)&1 == 1, big.NewInt(int64(1+i+2*a)))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	f.prepared, err = Prepare(p, f.keys, f.rows, f.active)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func fixedCipher(t *testing.T, a *Prepared, policy []bool) (*Ciphertext, GT) {
	t.Helper()
	msg := a.p.c.ScaleT(a.p.c.base, big.NewInt(17))
	ct, err := encryptWithCoins(a, policy, msg, big.NewInt(7), big.NewInt(11))
	if err != nil {
		t.Fatal(err)
	}
	return ct, msg
}
func decode(t *testing.T, f *fixture, a *Prepared, ct *Ciphertext, i int) (GT, error) {
	t.Helper()
	h, err := a.Help(i + 1)
	if err != nil {
		t.Fatal(err)
	}
	return Decapsulate(ct, h, f.secrets[i], f.masks[i])
}

func TestAsymmetricNativeBilinearity(t *testing.T) {
	c := testContext(t)
	if c.pairing.IsSymmetric() {
		t.Fatal("not asymmetric")
	}
	a, b := big.NewInt(19), big.NewInt(23)
	if !c.Pair(c.Scale1(c.g1, a), c.Scale2(c.g2, b)).Equal(c.ScaleT(c.base, c.mul(a, b))) {
		t.Fatal("native bilinearity")
	}
	if _, err := NewTrustedContext("type a\nr 641\n"); err == nil {
		t.Fatal("accepted symmetric interface")
	}
	t.Logf("functional fixture only: order_bits=%d G1=%d G2=%d GT=%d bytes", c.p.BitLen(), len(c.g1.Bytes()), len(c.g2.Bytes()), len(c.base.Bytes()))
}
func TestFourClassesAndPolicyIndependentHelp(t *testing.T) {
	f := fourClasses(t)
	for _, policy := range [][]bool{{true, false}, {false, true}, {true, true}, {false, false}} {
		ct, msg := fixedCipher(t, f.prepared, policy)
		for i := 0; i < 4; i++ {
			got, err := decode(t, f, f.prepared, ct, i)
			eligible := (!policy[0] || i&1 != 0) && (!policy[1] || i&2 != 0)
			if eligible {
				if err != nil || !got.Equal(msg) {
					t.Fatalf("qualified i=%d policy=%v err=%v", i, policy, err)
				}
			} else if !errors.Is(err, ErrUnqualified) {
				t.Fatalf("missing qualification check i=%d: %v", i, err)
			}
		}
	}
}
func TestFullSourcePostprocessing(t *testing.T) {
	f := fourClasses(t)
	p := f.p
	c := p.c
	s, z := big.NewInt(7), big.NewInt(11)
	for _, policy := range [][]bool{{true, false}, {false, true}, {true, true}, {false, false}} {
		ct, _ := fixedCipher(t, f.prepared, policy)
		for _, rho := range []*big.Int{big.NewInt(2), big.NewInt(5)} {
			ub := make([]G1, p.dim()+1)
			for w := 0; w < p.dim(); w++ {
				ub[w] = c.zero1()
				for i := 0; i <= p.N; i++ {
					ub[w] = c.Add1(ub[w], p.U[w][i])
				}
			}
			ub[p.dim()] = p.T0
			for i := 0; i < p.N; i++ {
				row := c.Add1(f.keys[i].T, c.Neg1(p.U[p.a()][i+1]))
				for a := 0; a < p.M; a++ {
					row = c.Add1(row, c.Neg1(p.U[a][i+1]))
					if policy[a] && f.active[i][a] {
						row = c.Add1(row, f.rows[i][a].E)
					}
				}
				ub[p.dim()] = c.Add1(ub[p.dim()], row)
			}
			full := make([]G1, p.dim()+1)
			for w := range full {
				full[w] = c.Add1(c.Scale1(p.H, s), c.Neg1(c.Scale1(ub[w], z)))
				if (w < p.M && policy[w]) || w == p.M+3 {
					full[w] = c.Add1(full[w], c.Scale1(p.H, rho))
				}
			}
			k := int64(0)
			for _, x := range policy {
				if x {
					k++
				}
			}
			dp := c.Add1(full[p.a()], c.Add1(full[p.dim()], c.Scale1(full[p.b()], big.NewInt(k))))
			for a, use := range policy {
				if !use {
					dp = c.Add1(dp, full[a])
				}
			}
			if !dp.Equal(ct.DP) || !c.Add1(full[p.cc()], c.Neg1(full[p.b()])).Equal(ct.DC) || !full[p.rr()].Equal(ct.DR) {
				t.Fatalf("source projection mismatch policy=%v rho=%s", policy, rho)
			}
		}
	}
}
func TestPartialRevocationRetainsOtherQualificationAndOldState(t *testing.T) {
	f := fourClasses(t)
	old, msg := fixedCipher(t, f.prepared, []bool{true, true})
	f.active[3][0] = false
	current, err := Prepare(f.p, f.keys, f.rows, f.active)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := fixedCipher(t, current, []bool{true, true})
	if _, err = decode(t, f, current, ct, 3); !errors.Is(err, ErrUnqualified) {
		t.Fatal("A revocation missing", err)
	}
	ctB, keyB := fixedCipher(t, current, []bool{false, true})
	got, err := decode(t, f, current, ctB, 3)
	if err != nil || !got.Equal(keyB) {
		t.Fatal("B lost after only A revoked", err)
	}
	got, err = decode(t, f, f.prepared, old, 3)
	if err != nil || !got.Equal(msg) {
		t.Fatal("old state was incorrectly destroyed", err)
	}
	h, _ := f.prepared.Help(4)
	if _, err = Decapsulate(ctB, h, f.secrets[3], f.masks[3]); err == nil {
		t.Fatal("mixed local snapshot accepted")
	}
}
func TestProjectionTamperingInactiveRowsAndOrder(t *testing.T) {
	f := fourClasses(t)
	p := f.p
	c := p.c
	bad := *f.keys[0]
	bad.P = append([]G2(nil), bad.P...)
	bad.P[1] = c.Add2(bad.P[1], c.g2)
	if CheckKeyProjections(p, &bad) == nil {
		t.Fatal("changed raw projection accepted")
	}
	bad = *f.keys[0]
	bad.P = append([]G2(nil), bad.P...)
	bad.P[0] = c.zero2()
	if CheckKeyProjections(p, &bad) == nil {
		t.Fatal("self projection accepted")
	}
	badRow := *f.rows[0][0]
	badRow.F = append([]G2(nil), badRow.F...)
	badRow.F[1] = G2{}
	f.rows[0][0] = &badRow
	f.active[0][0] = false
	if _, err := Prepare(p, f.keys, f.rows, f.active); err == nil {
		t.Fatal("omitted inactive coordinate accepted")
	}
	if _, err := Decapsulate(nil, nil, nil, nil); err == nil {
		t.Fatal("nil decoder input")
	}
	f = fourClasses(t)
	f.rows[0][0], f.rows[0][1] = f.rows[0][1], f.rows[0][0]
	if _, err := Prepare(f.p, f.keys, f.rows, f.active); err == nil {
		t.Fatal("reordered namespaces accepted")
	}
}
func TestProjectionCheckIsNotKnowledgeProof(t *testing.T) {
	f := fourClasses(t)
	p := f.p
	c := p.c
	// Constructed from public points only: the scalar -u_A/u_R is not an
	// input to this operation. It must NOT be called a proven canonical root.
	k := &RawKey{p: p, Slot: 1, T: p.U[0][1], P: make([]G2, p.N)}
	for j := 1; j < p.N; j++ {
		k.P[j] = c.Neg2(p.W[j][1][0])
	}
	if err := CheckKeyProjections(p, k); err != nil {
		t.Fatal("public consistency example rejected", err)
	}
}
func TestOneShotSetupFailuresAndCorrelatedDummy(t *testing.T) {
	c := testContext(t)
	for _, which := range []string{"t", "ur", "balance"} {
		s := fixedCoins(2, 2)
		switch which {
		case "t":
			s.t[0] = big.NewInt(0)
		case "ur":
			s.u[6][1] = big.NewInt(0)
		case "balance":
			s.u[3][1] = new(big.Int).Set(s.u[4][1])
		}
		p, err := setupWithCoins(c, 2, 2, s)
		if !errors.Is(err, ErrSetupDegenerate) || p == nil || p.ready {
			t.Fatalf("not exact setup failure %s", which)
		}
		if _, _, _, err = UserKeyGen(p, 1, 2); err == nil {
			t.Fatal("used failed setup")
		}
	}
	s := fixedCoins(2, 2)
	for w := range s.u {
		s.u[w][0] = big.NewInt(0)
	}
	p, err := setupWithCoins(c, 2, 2, s)
	if err != nil || !p.T0.e.Is0() {
		t.Fatal("valid zero dummy inner product rejected", err)
	}
	for _, x := range p.P0 {
		if !x.e.Is0() {
			t.Fatal("dummy correlation not preserved")
		}
	}
	for j := range p.W {
		if p.W[j][j+1] != nil {
			t.Fatal("own-index CRS entry exists")
		}
	}
}
func TestKeyRetryCapAndCanonicalBoundaries(t *testing.T) {
	c := testContext(t)
	p, err := setupWithCoins(c, 2, 2, fixedCoins(2, 2))
	if err != nil {
		t.Fatal(err)
	}
	forbidden := c.neg(big.NewInt(4))
	calls := 0
	_, _, attempts, err := userKeyGen(p, 1, 3, func() (*big.Int, error) { calls++; return new(big.Int).Set(forbidden), nil })
	if !errors.Is(err, ErrKeyAttempts) || calls != 3 || len(attempts) != 3 {
		t.Fatal("key retries not capped/retained")
	}
	for _, a := range attempts {
		if a.Accepted || CheckKeyProjections(p, a.Raw) == nil {
			t.Fatal("forbidden normalization accepted")
		}
	}
	calls = 0
	k, secret, attempts, err := userKeyGen(p, 1, 3, func() (*big.Int, error) {
		calls++
		if calls == 1 {
			return new(big.Int).Set(forbidden), nil
		}
		return big.NewInt(2), nil
	})
	if err != nil || len(attempts) != 2 || secret == nil || CheckKeyProjections(p, k) != nil {
		t.Fatal("first valid attempt not returned", err)
	}
	for _, r := range []*big.Int{big.NewInt(0), new(big.Int).Set(c.p), big.NewInt(-1)} {
		if _, _, err := rawKey(p, 1, r); err == nil {
			t.Fatal("noncanonical scalar accepted")
		}
	}
	x, _, err := increment(p, 1, 0, false, big.NewInt(0))
	if err != nil || CheckIncrementProjections(p, x) != nil || !x.E.e.Is0() {
		t.Fatal("allowed zero increment rejected", err)
	}
}
func TestProductionSamplersAndUniformGroupKEM(t *testing.T) {
	c := testContext(t)
	p, err := Setup(c, 2, 2)
	if err != nil {
		t.Fatal("one-shot production setup failed", err)
	}
	keys := make([]*RawKey, 2)
	secrets := make([]*KeySecret, 2)
	rows := make([][]*Increment, 2)
	local := make([][]*IncrementSecret, 2)
	active := [][]bool{{true, true}, {true, true}}
	for i := 0; i < 2; i++ {
		var attempts []KeyAttempt
		keys[i], secrets[i], attempts, err = UserKeyGen(p, i+1, 128)
		if err != nil || len(attempts) == 0 {
			t.Fatal(err)
		}
		rows[i] = make([]*Increment, 2)
		local[i] = make([]*IncrementSecret, 2)
		for a := 0; a < 2; a++ {
			rows[i][a], local[i][a], err = NewIncrement(p, i+1, a, true)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	a, err := Prepare(p, keys, rows, active)
	if err != nil {
		t.Fatal(err)
	}
	ct, key, err := Encapsulate(a, []bool{true, true})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		h, _ := a.Help(i + 1)
		got, err := Decapsulate(ct, h, secrets[i], local[i])
		if err != nil || !got.Equal(key) {
			t.Fatal("real sampler KEM correctness", err)
		}
	}
	if ct.AlgebraPayloadBytes() != 5*len(ct.CS.Bytes())+len(ct.CM.Bytes()) {
		t.Fatal("wrong core payload accounting")
	}
	// One prepared state reused for each new policy; no user traversal in Encrypt.
	c.ResetStats()
	if _, err = Encrypt(a, []bool{true, true}, key); err != nil {
		t.Fatal(err)
	}
	if c.Stats().Pairings != 0 {
		t.Fatal("online encryption unexpectedly pairs")
	}
}

func samePrepared(t *testing.T, a, b *Prepared) {
	t.Helper()
	if !a.p0.Equal(b.p0) || !a.jc.Equal(b.jc) || !a.jr.Equal(b.jr) {
		t.Fatal("constant cache mismatch")
	}
	for k := range a.pa {
		if !a.pa[k].Equal(b.pa[k]) {
			t.Fatal("public increment cache mismatch")
		}
	}
	for i, x := range a.helps {
		y := b.helps[i]
		if !x.k0.Equal(y.k0) || !x.kc.Equal(y.kc) || !x.kr.Equal(y.kr) {
			t.Fatal("constant help mismatch")
		}
		for k := range x.ka {
			if !x.ka[k].Equal(y.ka[k]) || x.active[k] != y.active[k] {
				t.Fatal("mutable help mismatch")
			}
		}
	}
}
func TestCachedReplacementEqualsRebuildAndPreservesHistory(t *testing.T) {
	f := fourClasses(t)
	original := f.prepared
	oldCT, oldKey := fixedCipher(t, original, []bool{true, true})
	oldLocal := append([]*IncrementSecret(nil), f.masks[3]...)
	// Exercise deselection, an inactive fresh denial, active denial, and grant.
	current := original
	for step, state := range []struct{ y, active bool }{{true, false}, {false, false}, {false, true}, {true, true}} {
		row, secret, err := increment(f.p, 4, 0, state.y, big.NewInt(int64(31+step)))
		if err != nil {
			t.Fatal(err)
		}
		current, err = ReplaceIncrement(current, row, state.active)
		if err != nil {
			t.Fatal(err)
		}
		f.rows[3][0] = row
		f.masks[3][0] = secret
		f.active[3][0] = state.active
		rebuilt, err := Prepare(f.p, f.keys, f.rows, f.active)
		if err != nil {
			t.Fatal(err)
		}
		samePrepared(t, current, rebuilt)
		ct, key := fixedCipher(t, current, []bool{false, true})
		got, err := decode(t, f, current, ct, 3)
		if err != nil || !got.Equal(key) {
			t.Fatal("cached A update lost B", err)
		}
		ct, key = fixedCipher(t, current, []bool{true, true})
		got, err = decode(t, f, current, ct, 3)
		if state.y && state.active {
			if err != nil || !got.Equal(key) {
				t.Fatal("new grant unusable", err)
			}
		} else if !errors.Is(err, ErrUnqualified) {
			t.Fatal("denial/selector not enforced", err)
		}
		// Caller mutations cannot retroactively alter cached selectors/rows.
		row.F = nil
	}
	h, _ := original.Help(4)
	got, err := Decapsulate(oldCT, h, f.secrets[3], oldLocal)
	if err != nil || !got.Equal(oldKey) {
		t.Fatal("cached update mutated old state", err)
	}
}
