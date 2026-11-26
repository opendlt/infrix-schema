package policyeval

import (
	"bytes"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func amount(v float64) *float64 { return &v }

// gtEscape is how encoding/json writes '>' inside a string.
const gtEscape = `\` + `u003e`

func capDoc() *PolicyDocument {
	return &PolicyDocument{
		ID: "cap", Name: "transfer cap", Type: "intent:transfer", Version: 3, DefaultEffect: EffectAllow,
		Rules: []DocumentRule{
			{ID: "big", Priority: 10, Condition: `scope::amount() > 1000`, Effect: EffectDeny, AuditMsg: "over the cap", Enabled: true},
			{ID: "alice", Priority: 5, Condition: `actor::identity() == "acc://alice.acme"`, Effect: EffectAllow, AuditMsg: "alice", Enabled: true},
			{ID: "off", Priority: 1, Condition: `scope::amount() > 0`, Effect: EffectDeny, AuditMsg: "disabled", Enabled: false},
		},
	}
}

func mustEncode(t *testing.T, d *PolicyDocument) []byte {
	t.Helper()
	c, err := EncodeDocument(d)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return c
}

// The document round-trips through its one canonical content, and the decision rule is first-match by priority with disabled rules
// skipped and the default otherwise.
func TestDocumentDecidesFirstMatchByPriority(t *testing.T) {
	content := mustEncode(t, capDoc())
	d, err := DecodeDocument(content)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	cases := []struct {
		s    Subject
		want Effect
		rule string
	}{
		{Subject{Actor: "acc://bob.acme", Amount: amount(10)}, EffectAllow, ""},
		{Subject{Actor: "acc://bob.acme", Amount: amount(5000)}, EffectDeny, "big"},
		// alice's rule has the higher priority (5 < 10), so it decides before the cap.
		{Subject{Actor: "acc://alice.acme", Amount: amount(5000)}, EffectAllow, "alice"},
	}
	for _, c := range cases {
		out, err := d.Decide(&SubjectOnlyContext{Subject: c.s})
		if err != nil {
			t.Fatalf("%+v: %v", c.s, err)
		}
		if out.Effect != c.want || out.MatchedRule != c.rule {
			t.Errorf("%+v: got %s/%q, want %s/%q", c.s, out.Effect, out.MatchedRule, c.want, c.rule)
		}
	}
}

// A rule that cannot be evaluated before the first match fails the decision closed; after the first match it cannot change the decision.
func TestDecideFailsClosedBeforeTheFirstMatchOnly(t *testing.T) {
	d := &PolicyDocument{ID: "r", Type: "t", DefaultEffect: EffectAllow, Rules: []DocumentRule{
		{ID: "role", Priority: 1, Condition: `actor::role("admin") == false`, Effect: EffectDeny, Enabled: true},
		{ID: "any", Priority: 2, Condition: `actor::identity() != ""`, Effect: EffectAllow, Enabled: true},
	}}
	if _, err := d.Decide(&SubjectOnlyContext{Subject: Subject{Actor: "a"}}); err == nil || !strings.Contains(err.Error(), "actor::role") {
		t.Fatalf("a state operand before the first match must fail closed, got %v", err)
	}
	d.Rules[0].Priority = 3
	out, err := d.Decide(&SubjectOnlyContext{Subject: Subject{Actor: "a"}})
	if err != nil || out.MatchedRule != "any" {
		t.Fatalf("a state operand after the first match must not be evaluated: %+v %v", out, err)
	}
	// scanAll keeps walking but does not raise the later error.
	rules, _ := compileDocument(d)
	SortRules(rules)
	ctx := &SubjectOnlyContext{Subject: Subject{Actor: "a"}}
	walked := 0
	out, err = Decide(rules, d.DefaultEffect, func(r Rule) (bool, error) { walked++; return r.Evaluate(ctx) }, true)
	if err != nil || out.MatchedRule != "any" || walked != 2 {
		t.Fatalf("scanAll: %+v %v walked=%d", out, err, walked)
	}
}

// Every non-canonical spelling of a document is refused, so one document has one address.
func TestDecodeDocumentRefusesNonCanonicalContent(t *testing.T) {
	content := mustEncode(t, capDoc())
	bad := map[string][]byte{
		"whitespace":    append([]byte(" "), content...),
		"trailing":      append(append([]byte{}, content...), []byte(`{}`)...),
		"unknown field": bytes.Replace(content, []byte(`{"id":"cap"`), []byte(`{"extra":1,"id":"cap"`), 1),
		"reordered":     bytes.Replace(content, []byte(`"id":"cap","name":"transfer cap"`), []byte(`"name":"transfer cap","id":"cap"`), 1),
		"null rules":    []byte(`{"id":"x","name":"","type":"t","version":0,"defaultEffect":"allow","rules":null}`),
		"bad effect":    bytes.Replace(content, []byte(`"defaultEffect":"allow"`), []byte(`"defaultEffect":"permit"`), 1),
		"no compile":    bytes.Replace(content, []byte(`scope::amount() `+gtEscape+` 1000`), []byte(`scope::amount( `+gtEscape), 1),
		"duplicate id":  bytes.Replace(content, []byte(`"id":"alice"`), []byte(`"id":"big"`), 1),
	}
	for name, b := range bad {
		if bytes.Equal(b, content) {
			t.Fatalf("%s: the mutation did not apply", name)
		}
		if _, err := DecodeDocument(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	big := make([]byte, MaxDocumentBytes+1)
	if _, err := DecodeDocument(big); !errors.Is(err, ErrDocumentTooLarge) {
		t.Errorf("oversized: %v", err)
	}
	// Bite: the canonical content itself decodes.
	if _, err := DecodeDocument(content); err != nil {
		t.Fatalf("canonical content refused: %v", err)
	}
}

// The compiler refuses a condition with more entries than one bytecode byte can address; before, byte(idx) wrapped and the VM read the
// wrong literal. Bite: 256 literals compile and evaluate correctly.
func TestCompilerRefusesIndexOverflow(t *testing.T) {
	cond := func(n int) string {
		parts := make([]string, 0, n/2)
		for i := 0; i < n/2; i++ {
			parts = append(parts, fmt.Sprintf(`scope::function() == "f%d"`, i))
		}
		return strings.Join(parts, " OR ")
	}
	if _, err := CompileExpression(cond(514)); err == nil || !strings.Contains(err.Error(), "more than 256") {
		t.Fatalf("257 operands compiled: %v", err)
	}
	cc, err := CompileExpression(cond(512))
	if err != nil {
		t.Fatalf("256 operands refused: %v", err)
	}
	for _, fn := range []string{"f0", "f255"} {
		ok, err := EvaluateCompiled(cc, &SubjectOnlyContext{Subject: Subject{Function: fn}})
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", fn, ok, err)
		}
	}
	if ok, _ := EvaluateCompiled(cc, &SubjectOnlyContext{Subject: Subject{Function: "f256"}}); ok {
		t.Fatal("f256 matched")
	}
}

// The subject resolves exactly its own operands; every other operand and every aggregation is refused by name.
func TestSubjectOnlyContextRefusesWhatItDoesNotCarry(t *testing.T) {
	c := &SubjectOnlyContext{Subject: Subject{Actor: "a", Contract: "c", Function: "f", BlockHeight: 7, Amount: amount(2.5)}}
	want := map[OperandSource]any{OpActorIdentity: "a", OpScopeContract: "c", OpScopeFunction: "f", OpFunctionName: "f", OpTimeBlockHeight: uint64(7), OpBlockHeight: uint64(7), OpScopeAmount: 2.5}
	for op, v := range want {
		got, err := c.ResolveOperand(op, nil)
		if err != nil || got != v {
			t.Errorf("%s: %v %v", OperandSourceName(op), got, err)
		}
	}
	for op := range OperandNames() {
		if _, ok := want[op]; ok {
			continue
		}
		if _, err := c.ResolveOperand(op, []string{"x"}); err == nil {
			t.Errorf("%s resolved from the subject", OperandSourceName(op))
		}
	}
	if _, err := c.ResolveAggregation(AggSum, OpValueOutflow, nil, 10, AggWindowBlocks); err == nil {
		t.Error("aggregation resolved")
	}
	c.Subject.Amount = nil
	if _, err := c.ResolveOperand(OpScopeAmount, nil); err == nil {
		t.Error("absent amount resolved")
	}
}

// FuzzDecodeDocumentAndDecide: the policy-input decoder and the decision never panic, and a decoded document re-encodes to exactly its
// content (one address).
func FuzzDecodeDocumentAndDecide(f *testing.F) {
	content, _ := EncodeDocument(capDoc())
	f.Add(content, "acc://alice.acme", 1000.5)
	f.Add([]byte(`{"id":"x","name":"","type":"t","version":0,"defaultEffect":"deny","rules":[]}`), "", 0.0)
	f.Fuzz(func(t *testing.T, data []byte, actor string, amt float64) {
		d, err := DecodeDocument(data)
		if err != nil {
			return
		}
		again, err := EncodeDocument(d)
		if err != nil || !bytes.Equal(again, data) {
			t.Fatalf("decoded document does not re-encode to its content: %v", err)
		}
		out, err := d.Decide(&SubjectOnlyContext{Subject: Subject{Actor: actor, Amount: &amt}})
		if err == nil && out.Effect != EffectAllow && out.Effect != EffectDeny {
			t.Fatalf("decision effect %q", out.Effect)
		}
	})
}

// The evaluator body is stdlib-only, so the verifier can share it without a dependency on the node.
func TestPolicyEvalIsStdlibOnly(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	files := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		files++
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ".") {
				t.Errorf("%s imports %q, not the standard library", e.Name(), p)
			}
		}
	}
	if files < 8 {
		t.Fatalf("parsed only %d production files; the fence would pass vacuously", files)
	}
}

// The parser reads the whole condition and only well-formed calls, and a number that does not parse is an error; each used to compile to
// something other than its text. Bite: the well-formed spelling of each compiles.
func TestParserRefusesWhatItUsedToReadPastOrGuess(t *testing.T) {
	pairs := [][2]string{
		{`actor::identity() == "a" garbage`, `actor::identity() == "a"`},
		{`scope::amount( > 5`, `scope::amount() > 5`},
		{`actor::role("a" "b") == true`, `actor::role("a", "b") == true`},
		{`actor::role("a",) == true`, `actor::role("a") == true`},
		{`scope::amount() > 1.2.3`, `scope::amount() > 1.2`},
		{`scope::amount() > 99999999999999999999`, `scope::amount() > 9999999999`},
		{`SUM(env::value_outflow(), 10 > 5`, `SUM(env::value_outflow(), 10) > 5`},
		{`actor::("a") == 1`, `actor::identity() == "a"`},
		{`scope::amount() > 1 FOR 3 BLOCKS x`, `scope::amount() > 1 FOR 3 BLOCKS`},
	}
	for _, p := range pairs {
		if _, err := CompileExpression(p[0]); err == nil {
			t.Errorf("%q compiled", p[0])
		}
		if _, err := CompileExpression(p[1]); err != nil {
			t.Errorf("bite: %q refused: %v", p[1], err)
		}
	}
}

type nilContext struct{}

func (nilContext) ResolveOperand(OperandSource, []string) (any, error) { return nil, nil }
func (nilContext) ResolveAggregation(AggregationFunc, OperandSource, []string, uint64, AggregationWindowUnit) (float64, error) {
	return 0, nil
}

// A context that answers an operand with no value has not resolved it: the condition is unevaluable instead of comparing "<nil>". Before,
// `actor::identity() != ""` held for a nil actor. Bite: an empty actor string evaluates (and does not match).
func TestVMRefusesANilOperand(t *testing.T) {
	cc, err := CompileExpression(`actor::identity() != ""`)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := EvaluateCompiled(cc, nilContext{}); err == nil || !strings.Contains(err.Error(), "resolved to no value") {
		t.Fatalf("a nil operand evaluated: %v %v", ok, err)
	}
	if ok, err := EvaluateCompiled(cc, &SubjectOnlyContext{Subject: Subject{Actor: ""}}); err != nil || ok {
		t.Fatalf("bite: an empty actor: %v %v", ok, err)
	}
}
