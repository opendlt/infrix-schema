// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package policyeval

import (
	"strings"
	"testing"
)

type orderingCtx struct{ v any }

func (c orderingCtx) ResolveOperand(OperandSource, []string) (interface{}, error) { return c.v, nil }

func (c orderingCtx) ResolveAggregation(AggregationFunc, OperandSource, []string, uint64, AggregationWindowUnit) (float64, error) {
	return 0, nil
}

// AN ORDERING NEVER COMPARES A VALUE IT CANNOT ORDER. The VM's ordering opcodes read both sides through toFloat, which answered 0 for every
// string and for every numeric kind it did not list: `scope::amount() > 1000` over the amount "5000" was 0 > 1000, false, so the deny rule
// it guarded did not fire, and `scope::amount() < 1000` over the amount "abc" was 0 < 1000, true, so an allow rule fired on no amount.
// A value orders as a number (every numeric kind, a string that parses as a finite number, a boolean as 1 or 0); anything else is an
// evaluation error, and the decision fails closed.
func TestAnOrderingComparesOnlyWhatItCanOrder(t *testing.T) {
	type named uint16
	holds := []struct {
		expr string
		v    any
		want bool
	}{
		{"scope::amount() > 1000", "5000", true},
		{"scope::amount() > 1000", " 5000 ", true},
		{"scope::amount() < 1000", "5000", false},
		{"scope::amount() >= 1000", int32(1000), true},
		{"scope::amount() <= 1000", float32(999.5), true},
		{"scope::amount() > 1000", uint32(4000), true},
		{"scope::amount() > 1000", named(2000), true},
		{"scope::amount() > 1000", int8(5), false},
		{"actor::role() > 0", true, true},
		{"actor::role() > 0", false, false},
		{"scope::amount() > 1000", float64(1001), true},
	}
	for _, c := range holds {
		cc, err := CompileExpression(c.expr)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		got, _, err := NewVM(10000).Evaluate(cc, orderingCtx{c.v})
		if err != nil || got != c.want {
			t.Errorf("%s over %#v = %v, %v; want %v", c.expr, c.v, got, err, c.want)
		}
	}
	unevaluable := []struct {
		expr string
		v    any
	}{
		{"scope::amount() > 1000", "abc"},
		{"scope::amount() < 1000", "abc"},
		{"scope::amount() < 1000", ""},
		{"scope::amount() >= 1000", "NaN"},
		{"scope::amount() <= 1000", "-Inf"},
		{"scope::amount() > 1000", []byte("5000")},
		{"scope::amount() > 1000", struct{}{}},
	}
	for _, c := range unevaluable {
		cc, err := CompileExpression(c.expr)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		got, _, err := NewVM(10000).Evaluate(cc, orderingCtx{c.v})
		if err == nil || got || !strings.Contains(err.Error(), "not evaluable") {
			t.Errorf("%s over %#v = %v, %v; want an unevaluable ordering", c.expr, c.v, got, err)
		}
	}
}
