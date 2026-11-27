// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package policyeval

import (
	"strings"
	"testing"
)

// ACTOR::ROLE IS ANSWERED ONLY FROM PROVEN ROLES (infrix-core L3112): a proven actor's role answers TruthOperand, a proven empty set answers
// false (so a deny over a role it does not hold does not fire), and an unproven actor refuses, exactly as the subject-only context does.
func TestS28coActorRoleIsAnsweredOnlyFromProvenRoles(t *testing.T) {
	doc := &PolicyDocument{ID: "t", Name: "t", Type: "authorization", Version: 1, DefaultEffect: EffectDeny, Rules: []DocumentRule{
		{ID: "deny-suspended", Priority: 10, Condition: `actor::role("suspended") == 1`, Effect: EffectDeny, AuditMsg: "suspended", Enabled: true},
		{ID: "allow-admin", Priority: 100, Condition: `actor::role("Admin") == 1`, Effect: EffectAllow, AuditMsg: "admin", Enabled: true},
	}}
	subject := Subject{Actor: "acc://alice.acme"}
	out, err := doc.Decide(&ProvenRolesContext{Subject: subject, ActorRoles: []string{"admin"}, ActorProven: true})
	if err != nil || !out.Allowed() || out.MatchedRule != "allow-admin" {
		t.Fatalf("a proven admin: %+v %v; want allow-admin", out, err)
	}
	out, err = doc.Decide(&ProvenRolesContext{Subject: subject, ActorRoles: []string{}, ActorProven: true})
	if err != nil || out.Allowed() || out.MatchedRule != "" {
		t.Fatalf("an actor proven to hold no role: %+v %v; want the default deny", out, err)
	}
	out, err = doc.Decide(&ProvenRolesContext{Subject: subject, ActorRoles: []string{"admin", "suspended"}, ActorProven: true})
	if err != nil || out.Allowed() || out.MatchedRule != "deny-suspended" {
		t.Fatalf("a proven suspended admin: %+v %v; want deny-suspended", out, err)
	}
	if _, err := doc.Decide(&ProvenRolesContext{Subject: subject, ActorRoles: []string{"admin"}}); err == nil || !strings.Contains(err.Error(), "not proven") {
		t.Fatalf("an unproven actor: %v; want the operand refused as not proven", err)
	}
	if TruthOperand(true) != 1 || TruthOperand(false) != 0 {
		t.Fatal("TruthOperand is not 1/0")
	}
}

// ACTOR::HAS_KEY IS RE-DECIDED FROM THE PROVEN KEY PAGES THROUGH THE NODE'S OWN BODY (infrix-core L3196): a proven page answers 1; any other
// account is refused (its absence is not provable), never answered 0.
func TestS28ctActorHasKeyIsReDecidedFromTheProvenPages(t *testing.T) {
	c := &ProvenRolesContext{Subject: Subject{Actor: "acc://alice.acme"}, ProvenPages: map[string]bool{"acc://alice.acme/book/1": true}}
	if v, err := c.ResolveOperand(OpActorHasKey, []string{"acc://Alice.acme/book/1"}); err != nil || v != TruthOperand(true) {
		t.Fatalf("actor::has_key of a proven page = %v, %v; want 1", v, err)
	}
	if v, err := c.ResolveOperand(OpActorHasKey, []string{"acc://alice.acme/book/2"}); err == nil {
		t.Fatalf("actor::has_key of an unproven page answered %v", v)
	}
	if _, err := (&ProvenRolesContext{}).ResolveOperand(OpActorHasKey, nil); err == nil {
		t.Fatal("actor::has_key with no account answered")
	}
}
