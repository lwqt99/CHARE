package core

import (
	"strings"
	"testing"
)

func TestContextRejectsInconsistentParameters(t *testing.T) {
	for _, pair := range [][2]string{{"h 6279780", "h 6279792"}, {"exp1 7", "exp1 6"}} {
		if c, err := NewContext(strings.Replace(functionalParams, pair[0], pair[1], 1)); err == nil || c != nil {
			t.Fatal("inconsistent input reached a usable native context")
		}
	}
}
