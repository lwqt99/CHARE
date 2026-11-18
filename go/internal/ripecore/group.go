// Package ripecore implements only the frozen public-policy RIPE-BALANCED
// algebra. It is not the certified registration protocol or a measured peer of
// the authenticated CHARE implementation. In particular, projection checks are
// not proofs of knowledge. See docs/RIPE_CORE.md before using this package.
package ripecore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/Nik-U/pbc"
	"example.org/chare/internal/nativegroup"
)

// The wrappers keep source types separate, including for local callers. All
// operations allocate new elements; none mutates its operands. There is no
// untrusted point decoder or cross-source conversion API.
type G1 struct {
	e *pbc.Element
	c *Context
}
type G2 struct {
	e *pbc.Element
	c *Context
}
type GT struct {
	e *pbc.Element
	c *Context
}

type Stats struct {
	G1Adds, G1Scales, G2Adds, G2Scales, Pairings, TargetOps, ScalarDraws int64
	VectorDraws, GeneratorDraws                                          int64
}

// Context is single-threaded. Native parameter construction is for trusted
// locally generated/curated Type-F parameters, not arbitrary hostile input.
type Context struct {
	pairing         *pbc.Pairing
	p               *big.Int
	g1              G1
	g2              G2
	base            GT
	rng             io.Reader
	stats           Stats
	NativeAdmission nativegroup.Report
}

func NewTrustedContext(text string) (*Context, error) {
	fields := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 2 {
			return nil, errors.New("malformed Type-F parameter line")
		}
		if _, exists := fields[f[0]]; exists {
			return nil, errors.New("duplicate Type-F field")
		}
		fields[f[0]] = f[1]
	}
	if fields["type"] != "f" || len(fields) != 7 {
		return nil, errors.New("RIPE core requires trusted Type-F parameters")
	}
	for _, name := range []string{"q", "r", "b", "beta", "alpha0", "alpha1"} {
		x, ok := new(big.Int).SetString(fields[name], 10)
		if !ok || x.Sign() < 0 || x.BitLen() > 8192 || x.String() != fields[name] {
			return nil, fmt.Errorf("invalid %s", name)
		}
	}
	p, _ := new(big.Int).SetString(fields["r"], 10)
	q, _ := new(big.Int).SetString(fields["q"], 10)
	if p.Cmp(big.NewInt(3)) <= 0 || !p.ProbablyPrime(64) || !q.ProbablyPrime(64) {
		return nil, errors.New("nonprime or too-small trusted parameter")
	}
	pbc.SetCryptoRandom()
	pairing, admission, err := nativegroup.Open(text, false)
	if err != nil {
		return nil, err
	}
	if pairing.IsSymmetric() {
		return nil, errors.New("symmetric pairing is not the typed RIPE interface")
	}
	c := &Context{pairing: pairing, p: p, rng: rand.Reader, NativeAdmission: admission}
	for attempt := 0; attempt < 1024; attempt++ {
		c.g1 = G1{pairing.NewG1().Rand(), c}
		c.stats.GeneratorDraws++
		if !c.g1.e.Is0() {
			break
		}
	}
	for attempt := 0; attempt < 1024; attempt++ {
		c.g2 = G2{pairing.NewG2().Rand(), c}
		c.stats.GeneratorDraws++
		if !c.g2.e.Is0() {
			break
		}
	}
	if c.g1.e.Is0() || c.g2.e.Is0() {
		return nil, errors.New("native generator sampling failed")
	}
	c.base = c.Pair(c.g1, c.g2)
	if c.base.e.Is1() {
		return nil, errors.New("degenerate native pairing")
	}
	return c, nil
}

func (c *Context) Order() *big.Int            { return new(big.Int).Set(c.p) }
func (c *Context) Generator1() G1             { return c.g1 }
func (c *Context) Generator2() G2             { return c.g2 }
func (c *Context) TargetGenerator() GT        { return c.base }
func (c *Context) Stats() Stats               { return c.stats }
func (c *Context) ResetStats()                { c.stats = Stats{} }
func (c *Context) valid(x *big.Int) bool      { return x != nil && x.Sign() >= 0 && x.Cmp(c.p) < 0 }
func (c *Context) mod(x *big.Int) *big.Int    { return new(big.Int).Mod(new(big.Int).Set(x), c.p) }
func (c *Context) add(x, y *big.Int) *big.Int { return c.mod(new(big.Int).Add(x, y)) }
func (c *Context) mul(x, y *big.Int) *big.Int { return c.mod(new(big.Int).Mul(x, y)) }
func (c *Context) neg(x *big.Int) *big.Int    { return c.mod(new(big.Int).Neg(x)) }

// Nonzero sampling is an exact uniform draw in [1,p-1], not CRS resampling.
// crypto/rand's own entropy/read failures are returned, not hidden.
func (c *Context) sample(nonzero bool) (*big.Int, error) {
	bound := new(big.Int).Set(c.p)
	if nonzero {
		bound.Sub(bound, big.NewInt(1))
	}
	x, err := rand.Int(c.rng, bound)
	if err != nil {
		return nil, err
	}
	c.stats.ScalarDraws++
	if nonzero {
		x.Add(x, big.NewInt(1))
	}
	return x, nil
}
func randBelow(c *Context, bound *big.Int) (*big.Int, error) {
	x, err := rand.Int(c.rng, bound)
	if err == nil {
		c.stats.VectorDraws++
	}
	return x, err
}
func (c *Context) zero1() G1       { return G1{c.pairing.NewG1().Set0(), c} }
func (c *Context) zero2() G2       { return G2{c.pairing.NewG2().Set0(), c} }
func (c *Context) owns1(x G1) bool { return x.c == c && x.e != nil }
func (c *Context) owns2(x G2) bool { return x.c == c && x.e != nil }
func (c *Context) ownsT(x GT) bool { return x.c == c && x.e != nil }
func (c *Context) Add1(x, y G1) G1 {
	if !c.owns1(x) || !c.owns1(y) {
		panic("foreign G1 operand")
	}
	c.stats.G1Adds++
	return G1{c.pairing.NewG1().Add(x.e, y.e), c}
}
func (c *Context) Neg1(x G1) G1 {
	if !c.owns1(x) {
		panic("foreign G1 operand")
	}
	c.stats.G1Adds++
	return G1{c.pairing.NewG1().Neg(x.e), c}
}
func (c *Context) Scale1(x G1, a *big.Int) G1 {
	if !c.owns1(x) {
		panic("foreign G1 operand")
	}
	c.stats.G1Scales++
	return G1{c.pairing.NewG1().MulBig(x.e, c.mod(a)), c}
}
func (c *Context) Add2(x, y G2) G2 {
	if !c.owns2(x) || !c.owns2(y) {
		panic("foreign G2 operand")
	}
	c.stats.G2Adds++
	return G2{c.pairing.NewG2().Add(x.e, y.e), c}
}
func (c *Context) Neg2(x G2) G2 {
	if !c.owns2(x) {
		panic("foreign G2 operand")
	}
	c.stats.G2Adds++
	return G2{c.pairing.NewG2().Neg(x.e), c}
}
func (c *Context) Scale2(x G2, a *big.Int) G2 {
	if !c.owns2(x) {
		panic("foreign G2 operand")
	}
	c.stats.G2Scales++
	return G2{c.pairing.NewG2().MulBig(x.e, c.mod(a)), c}
}
func (c *Context) Pair(x G1, y G2) GT {
	if !c.owns1(x) || !c.owns2(y) {
		panic("foreign pairing operand")
	}
	c.stats.Pairings++
	return GT{c.pairing.NewGT().Pair(x.e, y.e), c}
}
func (c *Context) MulT(x, y GT) GT {
	if !c.ownsT(x) || !c.ownsT(y) {
		panic("foreign GT operand")
	}
	c.stats.TargetOps++
	return GT{c.pairing.NewGT().Mul(x.e, y.e), c}
}
func (c *Context) DivT(x, y GT) GT {
	if !c.ownsT(x) || !c.ownsT(y) {
		panic("foreign GT operand")
	}
	c.stats.TargetOps++
	return GT{c.pairing.NewGT().Div(x.e, y.e), c}
}
func (c *Context) ScaleT(x GT, a *big.Int) GT {
	if !c.ownsT(x) {
		panic("foreign GT operand")
	}
	c.stats.TargetOps++
	return GT{c.pairing.NewGT().PowBig(x.e, c.mod(a)), c}
}
func (x G1) Equal(y G1) bool {
	return x.c != nil && x.c == y.c && x.e != nil && y.e != nil && x.e.Equals(y.e)
}
func (x G2) Equal(y G2) bool {
	return x.c != nil && x.c == y.c && x.e != nil && y.e != nil && x.e.Equals(y.e)
}
func (x GT) Equal(y GT) bool {
	return x.c != nil && x.c == y.c && x.e != nil && y.e != nil && x.e.Equals(y.e)
}
func (x G1) Bytes() []byte { return x.e.Bytes() }
func (x G2) Bytes() []byte { return x.e.Bytes() }
func (x GT) Bytes() []byte { return x.e.Bytes() }

func (c *Context) RandomMessage() (GT, error) {
	x, err := c.sample(false)
	if err != nil {
		return GT{}, err
	}
	return c.ScaleT(c.base, x), nil
}
