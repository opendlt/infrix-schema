// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package policyeval

import "fmt"

// Subject is what a goal policy is decided over at intent admission: the requesting actor, the contract and function the goal targets,
// the block height, and the amount the goal moves. The node's admission context resolves these operands through Subject.Resolve (the same
// body), and the verifier re-runs a bundle's policies over the Subject the bundle commits to.
//
// Amount is nil when the goal states none; scope::amount then cannot be evaluated.
type Subject struct {
	Actor       string
	Contract    string
	Function    string
	BlockHeight uint64
	Amount      *float64
}

// Resolve answers the operands a Subject carries. handled is false for every other operand; the caller decides what that operand is
// (the node may read its own state for it; the verifier refuses it, because nothing it can check carries it).
func (s *Subject) Resolve(source OperandSource, _ []string) (value any, handled bool, err error) {
	switch source {
	case OpActorIdentity:
		return s.Actor, true, nil
	case OpScopeContract:
		return s.Contract, true, nil
	case OpScopeFunction, OpFunctionName:
		return s.Function, true, nil
	case OpTimeBlockHeight, OpBlockHeight:
		return s.BlockHeight, true, nil
	case OpScopeAmount:
		if s.Amount == nil {
			return nil, true, fmt.Errorf("%s: this goal states no amount (customParams.amount or a source asset amount)", OperandSourceName(source))
		}
		return *s.Amount, true, nil
	default:
		return nil, false, nil
	}
}

// SubjectOnlyContext evaluates over a Subject and nothing else: every operand the Subject does not carry, and every aggregation, is an
// error, so a rule that reads one cannot be shown to match or not and the decision fails closed. It is the verifier's context: the node's
// state (roles, balances, history) is never read from a bundle as if it were proof.
type SubjectOnlyContext struct {
	Subject Subject
}

// ResolveOperand implements EvalContext.
func (c *SubjectOnlyContext) ResolveOperand(source OperandSource, args []string) (any, error) {
	v, handled, err := c.Subject.Resolve(source, args)
	if !handled {
		return nil, fmt.Errorf("operand %s is not carried by the policy subject and is not provable offline", OperandSourceName(source))
	}
	return v, err
}

// ResolveAggregation implements EvalContext: an aggregation reads history, which the subject does not carry.
func (c *SubjectOnlyContext) ResolveAggregation(fn AggregationFunc, source OperandSource, _ []string, _ uint64, _ AggregationWindowUnit) (float64, error) {
	return 0, fmt.Errorf("aggregation %v over %s reads history, which the policy subject does not carry and is not provable offline", fn, OperandSourceName(source))
}
