// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package intent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"testing"
)

// A goal constant that is not in ValidGoalTypes is a goal the node REJECTS; an
// entry in ValidGoalTypes with no constant is a goal no Go caller can name. Both
// are drift, and nothing tied the two together: this module's only tests were
// import fences. infrix-core derives its goal census, its conformance suite and
// its counts from ValidGoalTypes, so a constant declared but left out of the map
// (or the reverse) changes what "every goal" means across the whole release.

// declaredGoalValues parses types.go and returns the string value of every
// constant whose declared type is IntentGoalType.
func declaredGoalValues(t *testing.T) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "types.go", nil, 0)
	if err != nil {
		t.Fatalf("parse types.go: %v", err)
	}
	out := map[string]string{} // value -> constant name
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, s := range gd.Specs {
			vs, ok := s.(*ast.ValueSpec)
			if !ok {
				continue
			}
			id, ok := vs.Type.(*ast.Ident)
			if !ok || id.Name != "IntentGoalType" {
				continue
			}
			for i, v := range vs.Values {
				lit, ok := v.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING || i >= len(vs.Names) {
					t.Fatalf("goal constant %v is not a string literal; the vocabulary test cannot read it", vs.Names)
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("goal constant %s: %v", vs.Names[i].Name, err)
				}
				if prev, dup := out[val]; dup {
					t.Errorf("goal %q is declared twice: %s and %s", val, prev, vs.Names[i].Name)
				}
				out[val] = vs.Names[i].Name
			}
		}
	}
	return out
}

func TestEveryDeclaredGoalIsAValidGoalType(t *testing.T) {
	declared := declaredGoalValues(t)
	if len(declared) < 50 {
		t.Fatalf("read only %d goal constants from types.go; the test is not reading the vocabulary", len(declared))
	}
	var missing []string
	for val, name := range declared {
		if !ValidGoalTypes[IntentGoalType(val)] {
			missing = append(missing, name+" ("+val+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d goal constant(s) are declared but absent from ValidGoalTypes, so the node rejects them: %v", len(missing), missing)
	}
}

func TestEveryValidGoalTypeHasAConstant(t *testing.T) {
	declared := declaredGoalValues(t)
	var orphans []string
	for g, ok := range ValidGoalTypes {
		if !ok {
			t.Errorf("ValidGoalTypes[%q] is false: an entry that is present and false is neither valid nor absent", g)
			continue
		}
		if _, has := declared[string(g)]; !has {
			orphans = append(orphans, string(g))
		}
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Errorf("%d ValidGoalTypes entr(y/ies) have no Go constant, so no caller can name them: %v", len(orphans), orphans)
	}
	if len(ValidGoalTypes) != len(declared) {
		t.Errorf("ValidGoalTypes has %d entries but types.go declares %d goal constants", len(ValidGoalTypes), len(declared))
	}
}

var goalNameShape = regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$`)

func TestGoalValuesAreUpperSnakeCase(t *testing.T) {
	for val, name := range declaredGoalValues(t) {
		if !goalNameShape.MatchString(val) {
			t.Errorf("%s = %q is not UPPER_SNAKE_CASE; goal ids are matched byte for byte across the node, the CLI and every SDK", name, val)
		}
	}
}
