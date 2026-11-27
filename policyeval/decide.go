// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package policyeval

import (
	"fmt"
	"sort"
)

// Effect is the outcome of a matching rule, or a policy's default.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// RuleMaxGas is the gas budget one rule's condition may spend in the VM.
const RuleMaxGas = 100000

// Rule is one rule as the decision rule sees it. The node's expression and function rules and a policy document's rules implement it.
type Rule interface {
	GetID() string
	GetPriority() int
	GetEffect() Effect
	GetAuditMsg() string
	IsEnabled() bool
	Evaluate(ctx EvalContext) (bool, error)
}

// SortRules orders rules for evaluation: by priority, lower first, keeping the given order between equal priorities.
func SortRules(rules []Rule) {
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].GetPriority() < rules[j].GetPriority()
	})
}

// EvaluateCompiled runs a compiled condition under the rule gas budget. A rule with no compiled condition never matches.
func EvaluateCompiled(cc *CompiledCondition, ctx EvalContext) (bool, error) {
	if cc == nil {
		return false, nil
	}
	vm := NewVM(RuleMaxGas)
	result, _, err := vm.Evaluate(cc, ctx)
	return result, err
}

// Outcome is what the decision rule decided.
type Outcome struct {
	Effect Effect
	// MatchedRule is the ID of the first matching rule; empty when the default applied.
	MatchedRule string
	AuditMsg    string
}

// Allowed reports whether the outcome allows.
func (o Outcome) Allowed() bool { return o.Effect == EffectAllow }

// RuleEvaluator evaluates one rule for Decide: the rule's own Evaluate on the context, or a wrapper that also records a trace.
type RuleEvaluator func(r Rule) (bool, error)

// Decide is the first-match decision rule. Over rules already in evaluation order (SortRules), the first ENABLED rule whose condition
// matches decides; when none matches, the default effect applies.
//
// It FAILS CLOSED: a rule whose condition cannot be evaluated before the first match has not been shown not to match, so the decision is
// an error, never a skip. With scanAll the walk continues past the first match (a trace records every rule); an error after the first match
// cannot change the decision and is not raised.
func Decide(sorted []Rule, defaultEffect Effect, eval RuleEvaluator, scanAll bool) (Outcome, error) {
	var first Rule
	for _, r := range sorted {
		if !r.IsEnabled() {
			continue
		}
		matched, err := eval(r)
		if err != nil {
			if first == nil {
				return Outcome{}, fmt.Errorf("policy rule %s could not be evaluated: %w", r.GetID(), err)
			}
			continue
		}
		if matched && first == nil {
			first = r
			if !scanAll {
				break
			}
		}
	}
	if first != nil {
		return Outcome{Effect: first.GetEffect(), MatchedRule: first.GetID(), AuditMsg: first.GetAuditMsg()}, nil
	}
	return Outcome{Effect: defaultEffect, AuditMsg: fmt.Sprintf("no rule matched; default effect: %s", defaultEffect)}, nil
}
