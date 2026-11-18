// Package pbcparams checks the documented Type-A parameter identities before
// PBC's native parser sees the input. It does not certify cryptographic strength
// or turn a probable-prime test into a primality proof.
package pbcparams

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

const (
	MaxTextBytes    = 1 << 20
	MaxBits         = 16384
	PrimalityRounds = 64
	Profile         = "pbc-type-a-admission-v1"
)

type TypeA struct {
	R, Q, H                  *big.Int
	Exp1, Exp2, Sign1, Sign0 int
}

// Report describes executed input checks, not a security or primality certificate.
type Report struct {
	Profile             string `json:"profile"`
	BeforeNative        bool   `json:"before_native_parser"`
	StrictFields        bool   `json:"strict_fields"`
	Solinas             bool   `json:"solinas_identity"`
	Cofactor            bool   `json:"cofactor_identity"`
	Multiple12          bool   `json:"cofactor_multiple_of_12"`
	ProbablePrimeRounds int    `json:"probable_prime_rounds"`
	MaxIntegerBits      int    `json:"max_integer_bits"`
	SecurityCertified   bool   `json:"security_strength_certified"`
}

func (p *TypeA) Report() Report {
	return Report{Profile: Profile, BeforeNative: true, StrictFields: true,
		Solinas: true, Cofactor: true, Multiple12: true,
		ProbablePrimeRounds: PrimalityRounds, MaxIntegerBits: MaxBits}
}

// Parse accepts only the documented eight-field profile. This deliberately
// rejects comments, unknown fields and ambiguous numeric spellings. Whitespace
// may be ASCII spaces/tabs/CR/LF; accepted input bytes are passed to PBC unchanged.
func Parse(text string) (*TypeA, error) {
	if len(text) == 0 || len(text) > MaxTextBytes {
		return nil, errors.New("Type-A text must have 1 byte to 1 MiB")
	}
	for _, c := range []byte(text) {
		if c != '\n' && c != '\r' && c != '\t' && (c < 32 || c > 126) {
			return nil, errors.New("Type-A text must use printable ASCII or ASCII whitespace")
		}
	}
	allowed := map[string]bool{"type": true, "q": true, "h": true, "r": true, "exp1": true, "exp2": true, "sign1": true, "sign0": true}
	f := make(map[string]string, len(allowed))
	for _, line := range strings.Split(text, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		if len(parts) != 2 || !allowed[parts[0]] {
			return nil, errors.New("unknown field or malformed Type-A line")
		}
		if _, exists := f[parts[0]]; exists {
			return nil, fmt.Errorf("duplicate Type-A field %s", parts[0])
		}
		f[parts[0]] = parts[1]
	}
	if len(f) != len(allowed) || f["type"] != "a" {
		return nil, errors.New("complete eight-field Type-A parameters required")
	}
	positive := func(name string) (*big.Int, error) {
		s := f[name]
		if len(s) == 0 || len(s) > 5000 || s[0] == '0' {
			return nil, fmt.Errorf("%s must be a bounded positive decimal integer", name)
		}
		for _, c := range []byte(s) {
			if c < '0' || c > '9' {
				return nil, fmt.Errorf("invalid decimal %s", name)
			}
		}
		x, ok := new(big.Int).SetString(s, 10)
		if !ok || x.BitLen() > MaxBits {
			return nil, fmt.Errorf("%s exceeds %d bits", name, MaxBits)
		}
		return x, nil
	}
	p := new(TypeA)
	var err error
	if p.Q, err = positive("q"); err != nil {
		return nil, err
	}
	if p.R, err = positive("r"); err != nil {
		return nil, err
	}
	if p.H, err = positive("h"); err != nil {
		return nil, err
	}
	for name, dst := range map[string]*int{"exp1": &p.Exp1, "exp2": &p.Exp2} {
		x, e := positive(name)
		if e != nil || !x.IsInt64() || x.Int64() > MaxBits {
			return nil, fmt.Errorf("invalid or oversized %s", name)
		}
		*dst = int(x.Int64())
	}
	for name, dst := range map[string]*int{"sign1": &p.Sign1, "sign0": &p.Sign0} {
		if f[name] != "1" && f[name] != "-1" {
			return nil, fmt.Errorf("%s must be 1 or -1", name)
		}
		*dst, _ = strconv.Atoi(f[name])
	}
	if p.Exp1 >= p.Exp2 || p.R.Cmp(big.NewInt(3)) <= 0 || p.Q.Cmp(p.R) <= 0 {
		return nil, errors.New("require 0 < exp1 < exp2 and 3 < r < q")
	}
	r := new(big.Int).Lsh(big.NewInt(1), uint(p.Exp2))
	term := new(big.Int).Lsh(big.NewInt(int64(p.Sign1)), uint(p.Exp1))
	r.Add(r, term).Add(r, big.NewInt(int64(p.Sign0)))
	if r.Cmp(p.R) != 0 {
		return nil, errors.New("r disagrees with Solinas exponents/signs")
	}
	if new(big.Int).Mul(p.H, p.R).Cmp(new(big.Int).Add(p.Q, big.NewInt(1))) != 0 {
		return nil, errors.New("Type-A parameters require h*r = q+1")
	}
	if new(big.Int).Mod(p.H, big.NewInt(12)).Sign() != 0 {
		return nil, errors.New("documented Type-A profile requires h divisible by 12")
	}
	if !p.R.ProbablyPrime(PrimalityRounds) || !p.Q.ProbablyPrime(PrimalityRounds) {
		return nil, errors.New("r and q must pass the probable-prime checks")
	}
	return p, nil
}
