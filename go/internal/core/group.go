// Package core implements the rational-source algebra using an actual symmetric
// PBC pairing. Public aggregation never receives the setup or user secrets.
package core

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/Nik-U/pbc"
	"example.org/chare/internal/nativegroup"
	"example.org/chare/internal/pbcparams"
)

// Stats counts executed core operations, not estimates or security evidence.
type Stats struct {
	SourceOps, SourceAdds, SourceScales, Pairings, TargetOps, FieldSamples int64
}

// Context and its PBC elements are not safe for concurrent use.
type Context struct {
	Pairing         *pbc.Pairing
	P               *big.Int
	params          string
	rng             io.Reader
	stats           Stats
	NativeAdmission nativegroup.Report
}

func NewContext(params string) (*Context, error) {
	checked, err := pbcparams.Parse(params)
	if err != nil {
		return nil, fmt.Errorf("Type-A admission: %w", err)
	}
	pbc.SetCryptoRandom()
	pairing, admission, err := nativegroup.Open(params, true)
	if err != nil {
		return nil, fmt.Errorf("PBC parameters: %w", err)
	}
	if !pairing.IsSymmetric() {
		return nil, errors.New("rational core requires a symmetric pairing")
	}
	return &Context{Pairing: pairing, P: checked.R, params: params, rng: rand.Reader, NativeAdmission: admission}, nil
}

func (c *Context) Stats() Stats    { return c.stats }
func (c *Context) ResetStats()     { c.stats = Stats{} }
func (c *Context) ScalarSize() int { return (c.P.BitLen() + 7) / 8 }

// Sample follows the exact full/nonzero domain. A finite failed rejection loop
// is reported, never replaced by a fixed scalar or silently restarted setup.
func (c *Context) Sample(nonzero bool) (*big.Int, error) {
	for attempt := 0; attempt < 1024; attempt++ {
		v, err := rand.Int(c.rng, c.P)
		if err != nil {
			return nil, err
		}
		c.stats.FieldSamples++
		if !nonzero || v.Sign() != 0 {
			return v, nil
		}
	}
	return nil, errors.New("scalar rejection limit exceeded")
}

func (c *Context) ScalarBytes(x *big.Int) ([]byte, error) {
	if x == nil || x.Sign() < 0 || x.Cmp(c.P) >= 0 {
		return nil, errors.New("noncanonical scalar")
	}
	return x.FillBytes(make([]byte, c.ScalarSize())), nil
}
func (c *Context) ParseScalar(b []byte) (*big.Int, error) {
	if len(b) != c.ScalarSize() {
		return nil, errors.New("wrong scalar width")
	}
	x := new(big.Int).SetBytes(b)
	if x.Cmp(c.P) >= 0 {
		return nil, errors.New("scalar out of range")
	}
	return x, nil
}
func (c *Context) mod(x *big.Int) *big.Int           { return new(big.Int).Mod(new(big.Int).Set(x), c.P) }
func (c *Context) add(a, b *big.Int) *big.Int        { return c.mod(new(big.Int).Add(a, b)) }
func (c *Context) sub(a, b *big.Int) *big.Int        { return c.mod(new(big.Int).Sub(a, b)) }
func (c *Context) mul(a, b *big.Int) *big.Int        { return c.mod(new(big.Int).Mul(a, b)) }
func (c *Context) SourceZero() *pbc.Element          { return c.Pairing.NewG1().Set0() }
func (c *Context) clone(x *pbc.Element) *pbc.Element { return c.Pairing.NewG1().Set(x) }
func (c *Context) SourceAdd(a, b *pbc.Element) *pbc.Element {
	c.stats.SourceOps++
	c.stats.SourceAdds++
	return c.Pairing.NewG1().Add(a, b)
}
func (c *Context) SourceNeg(a *pbc.Element) *pbc.Element {
	c.stats.SourceOps++
	c.stats.SourceAdds++
	return c.Pairing.NewG1().Neg(a)
}
func (c *Context) SourceSub(a, b *pbc.Element) *pbc.Element { return c.SourceAdd(a, c.SourceNeg(b)) }
func (c *Context) SourceScale(a *pbc.Element, s *big.Int) *pbc.Element {
	c.stats.SourceOps++
	c.stats.SourceScales++
	return c.Pairing.NewG1().MulBig(a, c.mod(s))
}
func (c *Context) Pair(a, b *pbc.Element) *pbc.Element {
	c.stats.Pairings++
	return c.Pairing.NewGT().Pair(a, b)
}
func (c *Context) TargetMul(a, b *pbc.Element) *pbc.Element {
	c.stats.TargetOps++
	return c.Pairing.NewGT().Mul(a, b)
}
func (c *Context) TargetDiv(a, b *pbc.Element) *pbc.Element {
	c.stats.TargetOps++
	return c.Pairing.NewGT().Div(a, b)
}
func (c *Context) TargetScale(a *pbc.Element, s *big.Int) *pbc.Element {
	c.stats.TargetOps++
	return c.Pairing.NewGT().PowBig(a, c.mod(s))
}

// frame is length-delimited, with no hash substitution for its inputs.
func frame(tag string, fields ...[]byte) []byte {
	var out []byte
	all := append([][]byte{[]byte(tag)}, fields...)
	for _, b := range all {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		out = append(out, n[:]...)
		out = append(out, b...)
	}
	return out
}
func intBytes(v uint64) []byte { var b [8]byte; binary.BigEndian.PutUint64(b[:], v); return b[:] }
func pointsBytes(xs []*pbc.Element) []byte {
	f := make([][]byte, 0, len(xs)+1)
	f = append(f, intBytes(uint64(len(xs))))
	for _, x := range xs {
		f = append(f, x.Bytes())
	}
	return frame("points", f...)
}
