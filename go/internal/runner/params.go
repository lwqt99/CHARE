package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/Nik-U/pbc"
	"example.org/chare/internal/pbcparams"
)

type ParameterInfo struct {
	Type             string           `json:"type"`
	Origin           string           `json:"origin"`
	SHA256           string           `json:"sha256"`
	RBitsActual      int              `json:"r_bits_actual"`
	QBitsActual      int              `json:"q_bits_actual"`
	GBytes           uint             `json:"g_bytes_uncompressed"`
	GCompressedBytes uint             `json:"g_bytes_compressed"`
	GTBytes          uint             `json:"gt_bytes"`
	ScalarBytes      uint             `json:"pbc_zr_bytes"`
	PreparationNS    int64            `json:"curve_parameter_preparation_ns"`
	SecurityClaim    string           `json:"security_strength_claim"`
	Admission        pbcparams.Report `json:"admission"`
}

func prepareParameters(cfg Configuration) (text string, info ParameterInfo, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parameter preparation panic: %v", r)
		}
	}()
	pbc.SetCryptoRandom()
	start := time.Now()
	info.Type = "a"
	info.SecurityClaim = "none; parameter bit lengths are recorded, not calibrated security bits"
	if cfg.Curve.ParametersFile != "" {
		f, e := os.ReadFile(cfg.Curve.ParametersFile)
		if e != nil {
			return "", info, e
		}
		if len(f) == 0 || len(f) > 1<<20 {
			return "", info, errors.New("parameter file must contain 1 byte to 1 MiB")
		}
		text = string(f)
		info.Origin = "imported_public_parameter_file"
	} else {
		text = pbc.GenerateA(cfg.Curve.RBits, cfg.Curve.QBits).String()
		info.Origin = "generated_once_for_this_run"
	}
	checked, e := pbcparams.Parse(text)
	if e != nil {
		return "", info, e
	}
	r, q := checked.R, checked.Q
	info.Admission = checked.Report()
	for _, n := range cfg.Capacities {
		if r.Cmp(big.NewInt(int64(n)+1)) <= 0 {
			return "", info, errors.New("subgroup order must exceed every requested capacity plus one")
		}
	}
	pairing, e := pbc.NewPairingFromString(text)
	if e != nil {
		return "", info, e
	}
	if !pairing.IsSymmetric() {
		return "", info, errors.New("imported pairing is not symmetric")
	}
	info.PreparationNS = time.Since(start).Nanoseconds()
	info.RBitsActual, info.QBitsActual = r.BitLen(), q.BitLen()
	info.GBytes, info.GCompressedBytes = pairing.G1Length(), pairing.G1CompressedLength()
	info.GTBytes, info.ScalarBytes = pairing.GTLength(), pairing.ZrLength()
	h := sha256.Sum256([]byte(text))
	info.SHA256 = hex.EncodeToString(h[:])
	return text, info, nil
}
