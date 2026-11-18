// Package nativegroup validates native group construction before any protocol
// setup coins are drawn. PBC 0.5.14 caches a random subgroup base at field
// initialization; if that base is the identity, all later Rand calls are zero.
package nativegroup

import (
	"errors"
	"fmt"
	"github.com/Nik-U/pbc"
)

const MaxInitializations = 8
const ProbesPerSource = 32

type Report struct {
	Initializations   int `json:"initializations"`
	SourceProbes      int `json:"source_probes"`
	RejectedInstances int `json:"rejected_instances"`
}

// Open reuses the SAME trusted public curve parameters. It neither requests a
// new curve nor reruns protocol Setup; no alpha, user key or record yet exists.
// A nonzero probe certifies that the cached source base is nonzero. Fresh Rand
// values in an admitted prime-order source then have the original uniform law.
// Native initialization errors and exhaustion are explicit environment errors,
// not probabilities imported into a cryptographic theorem.
func Open(parameters string, symmetric bool) (*pbc.Pairing, Report, error) {
	return admit(func() (*pbc.Pairing, error) { return pbc.NewPairingFromString(parameters) }, symmetric)
}

func admit(build func() (*pbc.Pairing, error), symmetric bool) (*pbc.Pairing, Report, error) {
	var report Report
	for attempt := 0; attempt < MaxInitializations; attempt++ {
		report.Initializations++
		pairing, err := build()
		if err != nil {
			return nil, report, err
		}
		if pairing.IsSymmetric() != symmetric {
			return nil, report, errors.New("native source-type mismatch")
		}
		good := false
		for j := 0; j < ProbesPerSource; j++ {
			report.SourceProbes++
			if !pairing.NewG1().Rand().Is0() {
				good = true
				break
			}
		}
		if good && !symmetric {
			good = false
			for j := 0; j < ProbesPerSource; j++ {
				report.SourceProbes++
				if !pairing.NewG2().Rand().Is0() {
					good = true
					break
				}
			}
		}
		if good {
			return pairing, report, nil
		}
		report.RejectedInstances++
	}
	return nil, report, fmt.Errorf("native group admission exhausted after %d initializations", report.Initializations)
}
