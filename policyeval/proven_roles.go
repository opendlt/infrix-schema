// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package policyeval

import (
	"fmt"
	"strings"
)

// TruthOperand is a boolean operand's value under the EvalContext contract: a boolean operand (actor::role, actor::has_key, access::allowed,
// approval::has, approval::credential) resolves to 1.0 for true and 0.0 for false. Every context resolves its boolean operands through it
// (infrix-core policy.TruthOperand is this body), so the same question answers the same value on the node and in the verifier.
func TruthOperand(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// ProvenRolesContext evaluates over a Subject, the subject actor's global roles AS PROVEN against a bundle's state root (infrix-core L3112) and
// the key pages the bundle proves under the pin (actor::has_key, L3196):
// actor::role(r) answers TruthOperand(r is one of ActorRoles) only when ActorProven is set (the verifier set it after a RoleRecordProof for
// the subject's actor verified); otherwise it refuses, exactly as SubjectOnlyContext does. Every other operand is the Subject's, and every
// aggregation refuses (history is not proven).
type ProvenRolesContext struct {
	Subject Subject
	// ActorRoles is the subject actor's global role set in record form (lower case); empty when the proof shows the actor holds none.
	ActorRoles  []string
	ActorProven bool
	// ProvenPages are the key pages (URL, lower case) the bundle proves under the verifier's pin (its verified KeyPageProofs): actor::has_key
	// answers through ResolveActorHasKey, true for a proven page and refused for any other (ErrAbsenceNotProvable, infrix-core L3196).
	ProvenPages map[string]bool
}

// ResolveOperand implements EvalContext.
func (c *ProvenRolesContext) ResolveOperand(source OperandSource, args []string) (any, error) {
	if source == OpActorRole {
		if !c.ActorProven {
			return nil, fmt.Errorf("operand %s is not proven for actor %q against the bundle's state root", OperandSourceName(source), c.Subject.Actor)
		}
		if len(args) == 0 {
			return TruthOperand(false), nil
		}
		want := strings.ToLower(strings.TrimSpace(args[0]))
		for _, r := range c.ActorRoles {
			if r == want {
				return TruthOperand(true), nil
			}
		}
		return TruthOperand(false), nil
	}
	if source == OpActorHasKey {
		return ResolveActorHasKey(ProvenPageExists(c.ProvenPages), args)
	}
	v, handled, err := c.Subject.Resolve(source, args)
	if !handled {
		return nil, fmt.Errorf("operand %s is not carried by the policy subject and is not provable offline", OperandSourceName(source))
	}
	return v, err
}

// ResolveAggregation implements EvalContext: an aggregation reads history, which is not proven.
func (c *ProvenRolesContext) ResolveAggregation(fn AggregationFunc, source OperandSource, _ []string, _ uint64, _ AggregationWindowUnit) (float64, error) {
	return 0, fmt.Errorf("aggregation %v over %s reads history, which the policy subject does not carry and is not provable offline", fn, OperandSourceName(source))
}
