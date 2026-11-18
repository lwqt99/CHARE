package core

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/Nik-U/pbc"
)

// Params contains only public group values, never a setup secret scalar.
type Params struct {
	Ctx           *Context
	N             int
	Nodes         []*big.Int
	G, H          *pbc.Element
	Y, W, T, A, B []*pbc.Element
	Gamma, Z      *pbc.Element
	ID            [32]byte // engineering index; complete public bytes are bound in contexts
}

func Setup(c *Context, n int) (*Params, error) {
	if c == nil || n < 2 || c.P.Cmp(big.NewInt(int64(n)+1)) <= 0 {
		return nil, errors.New("require N>=2 and p>N+1")
	}
	pp := &Params{Ctx: c, N: n, Nodes: make([]*big.Int, n), Y: make([]*pbc.Element, n), W: make([]*pbc.Element, n), T: make([]*pbc.Element, n), A: make([]*pbc.Element, n-1), B: make([]*pbc.Element, n-1)}
	for i := range pp.Nodes {
		pp.Nodes[i] = big.NewInt(int64(i + 1))
	}
	a, err := c.Sample(true)
	if err != nil {
		return nil, err
	}
	beta, err := c.Sample(true)
	if err != nil {
		return nil, err
	}
	theta, err := c.Sample(true)
	if err != nil {
		return nil, err
	}
	alpha, err := c.Sample(false)
	if err != nil {
		return nil, err
	}
	var tau *big.Int
	for tries := 0; tries < 1024; tries++ {
		tau, err = c.Sample(false)
		if err != nil {
			return nil, err
		}
		if tau.Cmp(big.NewInt(int64(n))) > 0 {
			break
		}
		tau = nil
	}
	if tau == nil {
		return nil, errors.New("tau exclusion sampling limit exceeded")
	}
	for tries := 0; tries < 1024; tries++ {
		pp.G = c.Pairing.NewG1().Rand()
		if !pp.G.Is0() {
			break
		}
		pp.G = nil
	}
	if pp.G == nil {
		return nil, errors.New("generator sampling failed")
	}
	pp.H = c.SourceScale(pp.G, theta)
	pow := big.NewInt(1)
	for k := 0; k < n; k++ {
		pp.Y[k] = c.SourceScale(pp.G, c.mul(a, pow))
		pp.T[k] = c.SourceScale(pp.H, pow)
		if k < n-1 {
			pp.A[k] = c.SourceScale(pp.H, c.mul(a, pow))
			pp.B[k] = c.SourceScale(pp.H, c.mul(beta, pow))
		}
		if k == n-1 {
			pp.Gamma = c.SourceScale(pp.H, c.add(alpha, c.mul(a, pow)))
		}
		pow = c.mul(pow, tau)
	}
	for i, t := range pp.Nodes {
		inv := new(big.Int).ModInverse(c.sub(tau, t), c.P)
		if inv == nil {
			return nil, errors.New("unexpected excluded tau")
		}
		pp.W[i] = c.SourceScale(pp.G, c.mul(beta, inv))
	}
	pp.Z = c.TargetScale(c.Pair(pp.G, pp.H), alpha)
	pp.ID = sha256.Sum256(pp.Bytes())
	return pp, nil
}

func (pp *Params) Bytes() []byte {
	return frame("CHARE-RATIONAL-CORE-v1/params", []byte(pp.Ctx.params), intBytes(uint64(pp.N)), pp.Ctx.P.Bytes(), pp.G.Bytes(), pp.H.Bytes(), pointsBytes(pp.Y), pointsBytes(pp.W), pointsBytes(pp.T), pointsBytes(pp.A), pointsBytes(pp.B), pp.Gamma.Bytes(), pp.Z.Bytes())
}
