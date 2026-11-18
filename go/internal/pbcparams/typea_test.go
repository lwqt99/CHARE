package pbcparams

import (
	"fmt"
	"strings"
	"testing"
)

const fixture = "type a\nq 4025338979\nh 6279780\nr 641\nexp2 9\nexp1 7\nsign1 1\nsign0 1\n"

func TestTypeAIdentityAndSigns(t *testing.T) {
	for _, text := range []string{fixture, strings.ReplaceAll(fixture, "\n", "\r\n"),
		"type a\nq 83\nh 12\nr 7\nexp2 3\nexp1 1\nsign1 -1\nsign0 1\n",
		"type a\nq 59\nh 12\nr 5\nexp2 3\nexp1 1\nsign1 -1\nsign0 -1\n",
		"type a\nq 131\nh 12\nr 11\nexp2 3\nexp1 2\nsign1 1\nsign0 -1\n"} {
		p, err := Parse(text)
		if err != nil {
			t.Fatal(err)
		}
		if p.Report().Profile != Profile || p.Report().SecurityCertified {
			t.Fatal("incorrect report")
		}
	}
}

func TestRejectInconsistentTypeA(t *testing.T) {
	// q and r stay prime in the first cases: the former admission's prime-only
	// check did not establish the identities actually consumed by PBC.
	for _, pair := range [][2]string{{"h 6279780", "h 6279792"}, {"exp1 7", "exp1 6"},
		{"sign0 1", "sign0 -1"}, {"sign1 1", "sign1 -1"}, {"exp1 7", "exp1 9"},
		{"exp2 9", "exp2 16385"}, {"q 4025338979", "q 4025338978"}} {
		if _, err := Parse(strings.Replace(fixture, pair[0], pair[1], 1)); err == nil {
			t.Fatal(pair)
		}
	}
	// Exact relations with composite r, or with composite q, still fail.
	for _, text := range []string{
		"type a\nq 107\nh 12\nr 9\nexp2 3\nexp1 1\nsign1 1\nsign0 -1\n",
		"type a\nq 155\nh 12\nr 13\nexp2 4\nexp1 1\nsign1 -1\nsign0 -1\n",
		// q=19,r=5 is an arithmetic pairing possibility outside this explicitly
		// documented h-multiple-of-12 profile. We do not claim it impossible.
		"type a\nq 19\nh 4\nr 5\nexp2 3\nexp1 1\nsign1 -1\nsign0 -1\n"} {
		if _, err := Parse(text); err == nil {
			t.Fatal("accepted incompatible profile")
		}
	}
}

func TestRejectAmbiguousAndOversizedTypeA(t *testing.T) {
	bad := []string{"", fixture + "r 641\n", fixture + "other 1\n", fixture + "# comment\n",
		fixture + "\x00", strings.Replace(fixture, "type a", "type\u00a0a", 1),
		strings.Replace(fixture, "r 641\n", "", 1), strings.Replace(fixture, "r 641", "r +641", 1),
		strings.Replace(fixture, "r 641", "r 0641", 1), strings.Replace(fixture, "type a", "type a1", 1),
		strings.Replace(fixture, "h 6279780", "h 0", 1), strings.Replace(fixture, "sign0 1", "sign0 0", 1),
		strings.Repeat(" ", MaxTextBytes+1), strings.Replace(fixture, "q 4025338979", "q "+strings.Repeat("9", 5001), 1)}
	for i, text := range bad {
		if _, err := Parse(text); err == nil {
			t.Fatal(fmt.Sprintf("accepted malformed input %d", i))
		}
	}
}
