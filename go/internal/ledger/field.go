// Package ledger checks the paper's declared, finite coefficient language.
// Inputs are explicit analysis data, not extracted secrets or group logarithms.
// A successful check is not a security proof for an undeclared protocol/history.
package ledger

import (
	"errors"
	"math/big"
)

type Vector []*big.Int
type Matrix []Vector

type field struct{ p *big.Int }

func zeros(n int) Vector {
	v := make(Vector, n)
	for i := range v {
		v[i] = new(big.Int)
	}
	return v
}
func matrix(m, n int) Matrix {
	a := make(Matrix, m)
	for i := range a {
		a[i] = zeros(n)
	}
	return a
}
func clone(v Vector) Vector {
	w := zeros(len(v))
	for i := range v {
		w[i].Set(v[i])
	}
	return w
}
func (f field) add(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Add(a, b), f.p) }
func (f field) sub(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Sub(a, b), f.p) }
func (f field) mul(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), f.p) }
func (f field) dot(a, b Vector) *big.Int {
	x := new(big.Int)
	for i := range a {
		x = f.add(x, f.mul(a[i], b[i]))
	}
	return x
}
func (f field) vector(v Vector, n int) bool {
	if len(v) != n {
		return false
	}
	for _, x := range v {
		if x == nil || x.Sign() < 0 || x.Cmp(f.p) >= 0 {
			return false
		}
	}
	return true
}
func (f field) shape(a Matrix, rows, cols int) bool {
	if len(a) != rows {
		return false
	}
	for _, row := range a {
		if !f.vector(row, cols) {
			return false
		}
	}
	return true
}
func trans(a Matrix, cols int) Matrix {
	b := matrix(cols, len(a))
	for i := range a {
		for j := range a[i] {
			b[j][i].Set(a[i][j])
		}
	}
	return b
}
func (f field) product(a, b Matrix, bcols int) Matrix {
	c := matrix(len(a), bcols)
	for i := range a {
		for k := range b {
			for j := 0; j < bcols; j++ {
				c[i][j] = f.add(c[i][j], f.mul(a[i][k], b[k][j]))
			}
		}
	}
	return c
}

// reduction records the actual row operations: r = transform * input.
type reduction struct {
	r, transform Matrix
	pivots       []int
	cols         int
}

func (f field) reduce(a Matrix, cols int, track bool) (reduction, error) {
	d := reduction{r: matrix(len(a), cols), cols: cols}
	if track {
		d.transform = matrix(len(a), len(a))
	}
	for i := range a {
		d.r[i] = clone(a[i])
		if track {
			d.transform[i][i].SetInt64(1)
		}
	}
	rank := 0
	for j := 0; j < cols && rank < len(a); j++ {
		pivot := rank
		for pivot < len(a) && d.r[pivot][j].Sign() == 0 {
			pivot++
		}
		if pivot == len(a) {
			continue
		}
		d.r[pivot], d.r[rank] = d.r[rank], d.r[pivot]
		if track {
			d.transform[pivot], d.transform[rank] = d.transform[rank], d.transform[pivot]
		}
		inv := new(big.Int).ModInverse(d.r[rank][j], f.p)
		if inv == nil {
			return reduction{}, errors.New("modulus is not a field for this pivot")
		}
		for k := range d.r[rank] {
			d.r[rank][k] = f.mul(d.r[rank][k], inv)
		}
		if track {
			for k := range d.transform[rank] {
				d.transform[rank][k] = f.mul(d.transform[rank][k], inv)
			}
		}
		for i := range a {
			if i == rank || d.r[i][j].Sign() == 0 {
				continue
			}
			s := new(big.Int).Set(d.r[i][j])
			for k := range d.r[i] {
				d.r[i][k] = f.sub(d.r[i][k], f.mul(s, d.r[rank][k]))
			}
			if track {
				for k := range d.transform[i] {
					d.transform[i][k] = f.sub(d.transform[i][k], f.mul(s, d.transform[rank][k]))
				}
			}
		}
		d.pivots = append(d.pivots, j)
		rank++
	}
	return d, nil
}
func (f field) null(a Matrix, cols int) (Matrix, error) {
	d, err := f.reduce(a, cols, false)
	if err != nil {
		return nil, err
	}
	isPivot := make([]bool, cols)
	for _, j := range d.pivots {
		isPivot[j] = true
	}
	var basis Matrix
	for j := 0; j < cols; j++ {
		if isPivot[j] {
			continue
		}
		v := zeros(cols)
		v[j].SetInt64(1)
		for i, k := range d.pivots {
			v[k] = f.sub(new(big.Int), d.r[i][j])
		}
		basis = append(basis, v)
	}
	return basis, nil
}

// solve returns x with A*x=rhs, or a dual row y with y*A=0 and y*rhs=1.
// A was fixed by reduce; this also handles zero rows and zero columns.
func (f field) solve(d reduction, rhs Vector) (x, dual Vector, err error) {
	if !f.vector(rhs, len(d.r)) {
		return nil, nil, errors.New("invalid right hand side")
	}
	b := zeros(len(rhs))
	for i := range b {
		b[i] = f.dot(d.transform[i], rhs)
	}
	for i := len(d.pivots); i < len(b); i++ {
		if b[i].Sign() != 0 {
			inv := new(big.Int).ModInverse(b[i], f.p)
			if inv == nil {
				return nil, nil, errors.New("noninvertible residual")
			}
			v := clone(d.transform[i])
			for j := range v {
				v[j] = f.mul(v[j], inv)
			}
			return nil, v, nil
		}
	}
	x = zeros(d.cols)
	for i, j := range d.pivots {
		x[j].Set(b[i])
	}
	return x, nil, nil
}
