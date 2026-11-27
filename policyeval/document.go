// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package policyeval

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// PolicyDocument is the content-addressed form of a policy set: exactly what the decision rule reads (the rules, in their priority order,
// and the default effect) plus the set's identity. Its content is the canonical encoding EncodeDocument writes, and its address is the
// SHA-256 of that content (ContentHash). A bundle carries it as evidence.PolicyRef{Hash, Content}; the verifier decodes it with
// DecodeDocument and re-runs Decide, so a recorded decision is never what G0 is credited from.
//
// A node policy set with Go-function rules has no content form (a function is not content): the node refuses to export one, and so a
// decision made under one is never re-evaluable and never credited.
type PolicyDocument struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Type          string         `json:"type"`
	Version       uint64         `json:"version"`
	DefaultEffect Effect         `json:"defaultEffect"`
	Rules         []DocumentRule `json:"rules"`
}

// DocumentRule is one expression rule of a PolicyDocument. An empty Condition never matches (the node's rule with no compiled condition).
type DocumentRule struct {
	ID        string `json:"id"`
	Priority  int    `json:"priority"`
	Condition string `json:"condition"`
	Effect    Effect `json:"effect"`
	AuditMsg  string `json:"auditMsg"`
	Enabled   bool   `json:"enabled"`
}

// The bounds a policy document must keep. A document over any of them is refused by name before it is evaluated.
const (
	MaxDocumentBytes  = 256 << 10
	MaxDocumentRules  = 1024
	MaxConditionBytes = 8 << 10
)

// Errors DecodeDocument and EncodeDocument return.
var (
	ErrDocumentTooLarge     = errors.New("policyeval: policy document exceeds MaxDocumentBytes")
	ErrDocumentNotCanonical = errors.New("policyeval: policy document is not in canonical encoding")
)

// ContentHash is the address of a policy document's content.
func ContentHash(content []byte) [32]byte { return sha256.Sum256(content) }

// EncodeDocument validates a document and writes its canonical content. A nil rule list encodes as an empty one.
func EncodeDocument(d *PolicyDocument) ([]byte, error) {
	if d == nil {
		return nil, errors.New("policyeval: nil policy document")
	}
	c := *d
	if c.Rules == nil {
		c.Rules = []DocumentRule{}
	}
	if _, err := compileDocument(&c); err != nil {
		return nil, err
	}
	content, err := json.Marshal(&c)
	if err != nil {
		return nil, fmt.Errorf("policyeval: encode policy document: %w", err)
	}
	if len(content) > MaxDocumentBytes {
		return nil, ErrDocumentTooLarge
	}
	return content, nil
}

// DecodeDocument reads a policy document's content. It refuses content over MaxDocumentBytes before parsing it, unknown fields, trailing
// data, and any encoding other than the canonical one (so one document has exactly one content and one address), and it compiles every
// rule's condition, refusing a document any of whose conditions does not compile.
func DecodeDocument(content []byte) (*PolicyDocument, error) {
	if len(content) > MaxDocumentBytes {
		return nil, ErrDocumentTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.DisallowUnknownFields()
	var d PolicyDocument
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("policyeval: decode policy document: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("policyeval: policy document has trailing data")
	}
	if d.Rules == nil {
		return nil, errors.New("policyeval: policy document rules must be an array")
	}
	canonical, err := json.Marshal(&d)
	if err != nil || !bytes.Equal(canonical, content) {
		return nil, ErrDocumentNotCanonical
	}
	if _, err := compileDocument(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Decide re-runs the decision rule over the document's rules against ctx: the rules in priority order, the first enabled match deciding,
// the default effect otherwise, failing closed on a rule that cannot be evaluated before the first match.
func (d *PolicyDocument) Decide(ctx EvalContext) (Outcome, error) {
	rules, err := compileDocument(d)
	if err != nil {
		return Outcome{}, err
	}
	SortRules(rules)
	return Decide(rules, d.DefaultEffect, func(r Rule) (bool, error) { return r.Evaluate(ctx) }, false)
}

// compileDocument validates a document and compiles its rules.
func compileDocument(d *PolicyDocument) ([]Rule, error) {
	if d.ID == "" {
		return nil, errors.New("policyeval: policy document has no id")
	}
	if d.Type == "" {
		return nil, fmt.Errorf("policyeval: policy document %s has no type", d.ID)
	}
	if !validEffect(d.DefaultEffect) {
		return nil, fmt.Errorf("policyeval: policy document %s default effect %q is neither allow nor deny", d.ID, d.DefaultEffect)
	}
	if len(d.Rules) > MaxDocumentRules {
		return nil, fmt.Errorf("policyeval: policy document %s has %d rules, more than MaxDocumentRules (%d)", d.ID, len(d.Rules), MaxDocumentRules)
	}
	seen := make(map[string]struct{}, len(d.Rules))
	rules := make([]Rule, 0, len(d.Rules))
	for i := range d.Rules {
		r := d.Rules[i]
		if r.ID == "" {
			return nil, fmt.Errorf("policyeval: policy document %s rule %d has no id", d.ID, i)
		}
		if _, dup := seen[r.ID]; dup {
			return nil, fmt.Errorf("policyeval: policy document %s repeats rule id %s", d.ID, r.ID)
		}
		seen[r.ID] = struct{}{}
		if !validEffect(r.Effect) {
			return nil, fmt.Errorf("policyeval: policy document %s rule %s effect %q is neither allow nor deny", d.ID, r.ID, r.Effect)
		}
		if len(r.Condition) > MaxConditionBytes {
			return nil, fmt.Errorf("policyeval: policy document %s rule %s condition exceeds MaxConditionBytes (%d)", d.ID, r.ID, MaxConditionBytes)
		}
		dr := &documentRule{r: r}
		if r.Condition != "" {
			cc, err := CompileExpression(r.Condition)
			if err != nil {
				return nil, fmt.Errorf("policyeval: policy document %s rule %s: compile: %w", d.ID, r.ID, err)
			}
			dr.compiled = cc
		}
		rules = append(rules, dr)
	}
	return rules, nil
}

func validEffect(e Effect) bool { return e == EffectAllow || e == EffectDeny }

// documentRule is a compiled DocumentRule.
type documentRule struct {
	r        DocumentRule
	compiled *CompiledCondition
}

func (d *documentRule) GetID() string       { return d.r.ID }
func (d *documentRule) GetPriority() int    { return d.r.Priority }
func (d *documentRule) GetEffect() Effect   { return d.r.Effect }
func (d *documentRule) GetAuditMsg() string { return d.r.AuditMsg }
func (d *documentRule) IsEnabled() bool     { return d.r.Enabled }
func (d *documentRule) Evaluate(ctx EvalContext) (bool, error) {
	return EvaluateCompiled(d.compiled, ctx)
}
