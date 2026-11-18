package bench

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/Nik-U/pbc"
	"example.org/chare/internal/auth"
	"example.org/chare/internal/core"
	"example.org/chare/internal/ledger"
)

type ServiceEvidence struct {
	Graph                 string `json:"graph"`
	Participants          int    `json:"participants"`
	Directions            int    `json:"directions"`
	Edges                 int    `json:"edges"`
	Contributions         int    `json:"contributions"`
	PadDeliveries         int    `json:"pad_deliveries"`
	AggregateEqual        bool   `json:"aggregate_equal"`
	StrictPrefixProtected bool   `json:"strict_prefix_protected"`
	OnePadProtected       bool   `json:"one_pad_protected"`
	CutPadsProtected      bool   `json:"cut_pads_protected"`
	RecoveryKeyEqual      bool   `json:"recovery_key_equal"`
	MaskGrant             string `json:"mask_grant"`
}

type serviceMaterial struct {
	owners         []*auth.Signer
	delta, epsilon []*big.Int
	canonical      []byte
}
type serviceEdge struct{ from, to int }

func modInt(p *big.Int, x *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Set(x), p) }
func zeroVector(n int) ledger.Vector {
	v := make(ledger.Vector, n)
	for i := range v {
		v[i] = new(big.Int)
	}
	return v
}
func zeroMatrix(n, m int) ledger.Matrix {
	a := make(ledger.Matrix, n)
	for i := range a {
		a[i] = zeroVector(m)
	}
	return a
}

// Inputs for both graph alternatives are identical. The study is a separate
// signed service namespace; it does not install or overwrite business versions.
// Each receiver obtains its two masks by actually opening the original capsule.
func (w *workload) serviceInputs() (*serviceMaterial, error) {
	if w.studyMaterial != nil {
		return w.studyMaterial, nil
	}
	n := len(w.roots)
	x := &serviceMaterial{owners: make([]*auth.Signer, n), delta: make([]*big.Int, n), epsilon: make([]*big.Int, n)}
	var public [][]byte
	if err := w.measure("CHARE-service-input", "holder_auth_keygen", "shared_tree_cycle", n, func() (int64, error) {
		var total int64
		for i := range x.owners {
			var e error
			x.owners[i], e = auth.Generate()
			if e != nil {
				return total, e
			}
			total += int64(len(x.owners[i].Public()))
		}
		return total, nil
	}); err != nil {
		return nil, err
	}
	if err := w.measure("CHARE-service-input", "issue_validate_deliver", "two_same_fact_generations", 2*n, func() (int64, error) {
		var total int64
		for i := range w.roots {
			for generation := 0; generation < 2; generation++ {
				row, scalar, e := core.Issue(w.pp, w.roots[i], w.truth[0][i])
				if e != nil {
					return total, e
				}
				meta := auth.Frame("CHARE/native-study/service-source/v1", w.pp.Bytes(), w.rootBytes[i], w.records[0][i].metadata, number(uint64(generation)), row.Bytes())
				capsule, e := SealScalar(w.ctx, w.pp.G, w.roots[i].Q, scalar, meta, w.issuers[0])
				if e != nil {
					return total, e
				}
				if e = core.ValidateRow(w.pp, w.roots[i], row); e != nil {
					return total, e
				}
				if e = ValidateDelivery(w.ctx, w.pp.G, w.roots[i].Q, capsule, meta, w.issuers[0].Public()); e != nil {
					return total, e
				}
				opened, e := OpenScalar(w.ctx, w.pp.G, w.secrets[i].Z, capsule, meta, w.issuers[0].Public())
				if e != nil {
					return total, e
				}
				if opened.Cmp(scalar) != 0 {
					return total, errors.New("service mask capsule mismatch")
				}
				if generation == 0 {
					x.delta[i] = opened
				} else {
					x.epsilon[i] = opened
				}
				wire := auth.Frame("CHARE/native-study/service-source-wire/v1", meta, row.Bytes(), DeliveryBytes(capsule), w.issuers[0].Public())
				public = append(public, wire)
				total += int64(len(wire))
			}
		}
		return total, nil
	}); err != nil {
		return nil, err
	}
	x.canonical = auth.Frame("CHARE/native-study/service-inputs/v1", public...)
	w.studyMaterial = x
	return x, nil
}

func (w *workload) studyService(cfg Config, kind string) error {
	x, err := w.serviceInputs()
	if err != nil {
		return err
	}
	n := len(w.roots)
	if n < 4 {
		return errors.New("paper service profile requires at least four holders")
	}
	directions := 2 // Same full envelope and same two weighted functions for both graphs.
	edges := make([]serviceEdge, 0, n)
	for i := 0; i < n-1; i++ {
		edges = append(edges, serviceEdge{i, i + 1})
	}
	if kind == "cycle" {
		edges = append(edges, serviceEdge{n - 1, 0})
	} else if kind != "tree" {
		return errors.New("unknown graph")
	}
	c := w.ctx
	scheme := "CHARE-service-" + kind
	evidence := ServiceEvidence{Graph: kind, Participants: n, Directions: directions, Edges: len(edges), MaskGrant: "explicit diagnostic opening of ordinary masks; never passed to the public service"}
	// Freeze an actual old empty-policy target before any contribution is made.
	target, err := core.PrepareTarget(w.prepared, nil)
	if err != nil {
		return err
	}
	ct, key, err := core.Encapsulate(target)
	if err != nil {
		return err
	}
	fields := [][]byte{w.pp.Bytes(), x.canonical, []byte(kind), number(uint64(cfg.Replicate)), number(uint64(directions))}
	for _, ed := range edges {
		fields = append(fields, number(uint64(ed.from)), number(uint64(ed.to)))
	}
	for _, owner := range x.owners {
		fields = append(fields, owner.Public())
	}
	plan := auth.Frame("CHARE/native-study/service-plan/v1", fields...)
	w.result.Measurements = append(w.result.Measurements, Measurement{Scheme: scheme, Operation: "plan_bytes", Mode: "complete_bound_plan", Bytes: int64(len(plan)), Count: 1, Detail: "actual serialization; excludes distribution fanout, charged separately below"})
	pads := make([][]*big.Int, directions)
	contributions := make([][]*pbc.Element, directions)
	weights := make([][]*big.Int, directions)
	for d := 0; d < directions; d++ {
		pads[d] = make([]*big.Int, len(edges))
		contributions[d] = make([]*pbc.Element, n)
		weights[d] = make([]*big.Int, n)
		for i := 0; i < n; i++ {
			weights[d][i] = new(big.Int).Exp(w.pp.Nodes[i], big.NewInt(int64(d)), c.P)
		}
	}
	if err = w.measure(scheme, "pad_sample_deliver_install", "all_directions", directions*len(edges), func() (int64, error) {
		var total int64
		for d := 0; d < directions; d++ {
			for j, ed := range edges {
				pad, e := c.Sample(false)
				if e != nil {
					return total, e
				}
				meta := auth.Frame("CHARE/native-study/internal-pad/v1", plan, number(uint64(d)), number(uint64(j)), number(uint64(ed.from)), number(uint64(ed.to)))
				capsule, e := SealScalar(c, w.pp.G, w.roots[ed.to].Q, pad, meta, x.owners[ed.from])
				if e != nil {
					return total, e
				}
				opened, e := OpenScalar(c, w.pp.G, w.secrets[ed.to].Z, capsule, meta, x.owners[ed.from].Public())
				if e != nil {
					return total, e
				}
				if opened.Cmp(pad) != 0 {
					return total, errors.New("pad installation failed")
				}
				pads[d][j] = pad
				total += int64(len(DeliveryBytes(capsule)))
				evidence.PadDeliveries++
			}
		}
		return total, nil
	}); err != nil {
		return err
	}
	if err = w.measure(scheme, "plan_readiness", "all_holders", n, func() (int64, error) {
		var total int64
		for i := range w.roots {
			msg := auth.Frame("CHARE/native-study/readiness/v1", plan, number(uint64(i)))
			sig := x.owners[i].Sign(msg)
			if !auth.Verify(x.owners[i].Public(), msg, sig) {
				return total, errors.New("readiness signature")
			}
			total += int64(len(msg) + len(sig))
		}
		return total, nil
	}); err != nil {
		return err
	}
	if err = w.measure(scheme, "contribute_and_authenticate", "all_directions", n*directions, func() (int64, error) {
		var total int64
		for d := 0; d < directions; d++ {
			for i := range w.roots {
				local := new(big.Int).Add(w.secrets[i].V, new(big.Int).Sub(x.delta[i], x.epsilon[i]))
				local.Mul(local, weights[d][i])
				for j, ed := range edges {
					if ed.from == i {
						local.Add(local, pads[d][j])
					}
					if ed.to == i {
						local.Sub(local, pads[d][j])
					}
				}
				contributions[d][i] = c.SourceScale(w.pp.H, modInt(c.P, local))
				msg := auth.Frame("CHARE/native-study/contribution/v1", plan, number(uint64(d)), number(uint64(i)), contributions[d][i].Bytes())
				sig := x.owners[i].Sign(msg)
				if !auth.Verify(x.owners[i].Public(), msg, sig) {
					return total, errors.New("contribution signature")
				}
				total += int64(len(msg) + len(sig))
				evidence.Contributions++
			}
		}
		return total, nil
	}); err != nil {
		return err
	}
	aggregates := make([]*pbc.Element, directions)
	if err = w.measure(scheme, "aggregate", "all_directions", directions, func() (int64, error) {
		var total int64
		for d := 0; d < directions; d++ {
			sum := c.SourceZero()
			for _, pt := range contributions[d] {
				sum = c.SourceAdd(sum, pt)
			}
			aggregates[d] = sum
			total += int64(len(sum.Bytes()))
		}
		return total, nil
	}); err != nil {
		return err
	}
	evidence.AggregateEqual = true
	for d := 0; d < directions; d++ {
		expected := c.SourceZero()
		for i := range w.roots {
			local := new(big.Int).Add(w.secrets[i].V, new(big.Int).Sub(x.delta[i], x.epsilon[i]))
			local.Mul(local, weights[d][i])
			expected = c.SourceAdd(expected, c.SourceScale(w.pp.H, modInt(c.P, local)))
		}
		evidence.AggregateEqual = evidence.AggregateEqual && expected.Equals(aggregates[d])
	}
	if err = w.check(scheme+"/aggregate_native_identity", evidence.AggregateEqual, "actual independent PBC sum equals the intended weighted output"); err != nil {
		return err
	}
	// The analysis sees captured public coefficients; it does not extract logs
	// from group points. The diagnostic mask opening is explicitly separate.
	strict, err := w.serviceAudit(scheme, edges, weights, n-1, nil, "strict_prefix")
	if err != nil {
		return err
	}
	one := []int{len(edges) - 1}
	oneProtected, err := w.serviceAudit(scheme, edges, weights, n-1, one, "one_pad_exposure")
	if err != nil {
		return err
	}
	cut := append([]int(nil), one...)
	if kind == "cycle" {
		cut = append(cut, len(edges)-2)
	}
	cutProtected, err := w.serviceAudit(scheme, edges, weights, n-1, cut, "boundary_pad_exposure")
	if err != nil {
		return err
	}
	complete, err := w.serviceAudit(scheme, edges, weights, n, nil, "completed_no_exposure")
	if err != nil {
		return err
	}
	evidence.StrictPrefixProtected = strict
	evidence.OnePadProtected = oneProtected
	evidence.CutPadsProtected = cutProtected
	if err = w.check(scheme+"/prefix_capability", strict && complete && !cutProtected && (oneProtected == (kind == "cycle")), "actual independent-pad coefficient transcript; stated individual pad observations"); err != nil {
		return err
	}
	// Realize the failure witness using only observed prefix points and the
	// explicitly opened ordinary masks and boundary pads. No core scalar enters
	// recovery: the holder-core values are used only above for local emission.
	L := c.SourceZero()
	for i := 0; i < n-1; i++ {
		L = c.SourceAdd(L, contributions[0][i])
		L = c.SourceSub(L, c.SourceScale(w.pp.H, modInt(c.P, new(big.Int).Sub(x.delta[i], x.epsilon[i]))))
	}
	for _, j := range cut {
		ed := edges[j]
		coefficient := int64(0)
		if ed.from < n-1 {
			coefficient++
		}
		if ed.to < n-1 {
			coefficient--
		}
		L = c.SourceSub(L, c.SourceScale(w.pp.H, modInt(c.P, new(big.Int).Mul(big.NewInt(coefficient), pads[0][j]))))
	}
	if err = w.measure(scheme, "recover_old_key", "explicit_mask_and_boundary_opening", 1, func() (int64, error) {
		Q, R, e := w.compileClippedRecovery(L)
		if e != nil {
			return 0, e
		}
		raw := c.TargetMul(c.Pair(ct.C0, R), c.Pair(ct.C1, Q))
		// core.frame deliberately differs from auth.Frame. Reproduce the
		// original KDF's length-delimited domain and fields, without auth prefix.
		var input []byte
		for _, field := range [][]byte{[]byte("CHARE-RATIONAL-CORE-v1/H_K"), ct.Context, ct.C0.Bytes(), ct.C1.Bytes(), raw.Bytes()} {
			input = binary.BigEndian.AppendUint64(input, uint64(len(field)))
			input = append(input, field...)
		}
		got := sha256.Sum256(input)
		evidence.RecoveryKeyEqual = bytes.Equal(got[:], key)
		if !evidence.RecoveryKeyEqual {
			return 0, errors.New("native recovery chain failed")
		}
		return int64(len(Q.Bytes()) + len(R.Bytes())), nil
	}); err != nil {
		return err
	}
	if err = w.check(scheme+"/old_key_native_recovery", evidence.RecoveryKeyEqual, "old ciphertext, original KDF context, actual prefix and permitted diagnostic openings"); err != nil {
		return err
	}
	w.result.Measurements = append(w.result.Measurements, Measurement{Scheme: scheme, Operation: "retained_pad_payload", Mode: "both_endpoints", Bytes: int64(2 * directions * len(edges) * c.ScalarSize()), Count: 2 * directions * len(edges), Detail: "canonical private scalar widths; no secret values exported; excludes object overhead"})
	w.result.Study.Services = append(w.result.Study.Services, evidence)
	return nil
}

func (w *workload) serviceAudit(scheme string, edges []serviceEdge, weights [][]*big.Int, visible int, opened []int, mode string) (bool, error) {
	n := len(w.roots)
	nd := len(weights)
	p := w.ctx.P
	in := ledger.Input{Modulus: p, Nodes: w.pp.Nodes, Slots: make([]int, 3*n), PadCount: nd * len(edges)}
	for i := 0; i < n; i++ {
		in.Slots[i] = i
		in.Slots[n+i] = i
		in.Slots[2*n+i] = i
	}
	for i := n; i < 3*n; i++ {
		row := zeroVector(3 * n)
		row[i].SetInt64(1)
		in.NumericalW = append(in.NumericalW, row)
		in.NumericalR = append(in.NumericalR, zeroVector(in.PadCount))
	}
	// Only first-direction boundary pads are disclosed. Other directions retain
	// fresh independent pads, so they cannot silently cancel those columns.
	for _, j := range opened {
		row := zeroVector(in.PadCount)
		row[j].SetInt64(1)
		in.NumericalR = append(in.NumericalR, row)
		in.NumericalW = append(in.NumericalW, zeroVector(3*n))
	}
	for d := 0; d < nd; d++ {
		for i := 0; i < visible; i++ {
			poly := zeroMatrix(3*n, n)
			poly[i][0].Set(weights[d][i])
			poly[n+i][0].Set(weights[d][i])
			poly[2*n+i][0] = modInt(p, new(big.Int).Neg(weights[d][i]))
			pads := zeroVector(in.PadCount)
			for j, ed := range edges {
				if ed.from == i {
					pads[d*len(edges)+j].SetInt64(1)
				}
				if ed.to == i {
					pads[d*len(edges)+j] = new(big.Int).Sub(p, big.NewInt(1))
				}
			}
			in.Points = append(in.Points, ledger.Point{Polynomial: poly, Pads: pads})
		}
	}
	F := zeroMatrix(3*n, n)
	for i := 0; i < n; i++ {
		F[i][i].SetInt64(1)
	}
	gamma := zeroVector(n)
	for i := 0; i < n; i++ {
		den := big.NewInt(1)
		for j := 0; j < n; j++ {
			if i != j {
				den.Mul(den, new(big.Int).Sub(w.pp.Nodes[i], w.pp.Nodes[j]))
				den.Mod(den, p)
			}
		}
		gamma[i] = new(big.Int).ModInverse(den, p)
		if gamma[i] == nil {
			return false, errors.New("repeated node")
		}
	}
	protected := false
	err := w.measure(scheme, "coefficient_audit", mode, 1, func() (int64, error) {
		a, e := ledger.New(in)
		if e != nil {
			return 0, e
		}
		r, e := a.Message(F, zeroVector(n), gamma)
		if e != nil {
			return 0, e
		}
		protected = r.Protected
		// Both mask generations carry the same fact displacement; cores carry zero.
		shift := zeroVector(3 * n)
		for i := 0; i < n; i++ {
			shift[n+i].SetInt64(1)
			shift[2*n+i].SetInt64(1)
		}
		// Fact check excludes the artificial mask grant, which is message-only.
		factIn := in
		factIn.NumericalW = in.NumericalW[2*n:]
		factIn.NumericalR = in.NumericalR[2*n:]
		fa, e := ledger.New(factIn)
		if e != nil {
			return 0, e
		}
		fr, e := fa.Facts(shift)
		if e != nil {
			return 0, e
		}
		if !fr.Compatible {
			return 0, errors.New("same-fact service mismatch")
		}
		return 0, nil
	})
	return protected, err
}

// Compile the first n-1 core sum against an old full-cohort empty-policy target.
// Polynomial interpolation and projections are public. No setup/core secret is
// needed, and the returned points are actually constructed in the source group.
func (w *workload) compileClippedRecovery(L *pbc.Element) (*pbc.Element, *pbc.Element, error) {
	n := len(w.roots)
	c := w.ctx
	p := c.P
	gam := zeroVector(n)
	for i := 0; i < n; i++ {
		den := big.NewInt(1)
		for j := 0; j < n; j++ {
			if i != j {
				den.Mul(den, new(big.Int).Sub(w.pp.Nodes[i], w.pp.Nodes[j]))
				den.Mod(den, p)
			}
		}
		gam[i] = new(big.Int).ModInverse(den, p)
	}
	sum := new(big.Int)
	for i := 0; i < n-1; i++ {
		sum.Add(sum, gam[i])
		sum.Mod(sum, p)
	}
	zeta := new(big.Int).ModInverse(sum, p)
	if zeta == nil {
		return nil, nil, errors.New("zero clipped interpolation coefficient")
	}
	zeta = modInt(p, new(big.Int).Neg(zeta))
	q := zeroVector(n)
	for i := 0; i < n-1; i++ {
		poly := ledger.Vector{big.NewInt(1)}
		for j := 0; j < n; j++ {
			if j == i {
				continue
			}
			next := zeroVector(len(poly) + 1)
			for d, x := range poly {
				next[d].Sub(next[d], new(big.Int).Mul(w.pp.Nodes[j], x))
				next[d].Mod(next[d], p)
				next[d+1].Add(next[d+1], x)
				next[d+1].Mod(next[d+1], p)
			}
			poly = next
		}
		coef := modInt(p, new(big.Int).Mul(zeta, gam[i]))
		for d := range q {
			q[d].Add(q[d], new(big.Int).Mul(coef, poly[d]))
			q[d].Mod(q[d], p)
		}
	}
	if q[n-1].Cmp(new(big.Int).Sub(p, big.NewInt(1))) != 0 {
		return nil, nil, fmt.Errorf("wrong leading coefficient")
	}
	Q := c.SourceZero()
	for d := range q {
		Q = c.SourceAdd(Q, c.SourceScale(w.pp.T[d], q[d]))
	}
	R := c.SourceAdd(w.pp.Gamma, c.SourceZero())
	for d := 0; d < n-1; d++ {
		R = c.SourceSub(R, c.SourceScale(w.pp.A[d], q[d]))
	}
	for i := 0; i < n; i++ {
		div := zeroVector(n - 1)
		div[n-2].Set(q[n-1])
		for d := n - 2; d > 0; d-- {
			div[d-1] = modInt(p, new(big.Int).Add(q[d], new(big.Int).Mul(w.pp.Nodes[i], div[d])))
		}
		for d := range div {
			R = c.SourceSub(R, c.SourceScale(w.roots[i].Proj[d], div[d]))
		}
	}
	R = c.SourceSub(R, c.SourceScale(L, zeta))
	return Q, R, nil
}
