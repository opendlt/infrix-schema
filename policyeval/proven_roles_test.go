// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package policyeval

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// ACTOR::HAS_KEY IS RE-DECIDED FROM WHAT THE BUNDLE PROVES THROUGH THE NODE'S OWN BODY (infrix-core L3196, main's ruling 2026-11-27): the page
// exists AND the subject (the actor, or the identity a second argument names) holds an entry on it. A proven page answers from its proven entries
// (a subject absent from a proven page is a proven 0); a page past its proven book's page count is a proven 0; anything else is refused by name
// (ErrAbsenceNotProvable), never answered 0.
func TestS28cuActorHasKeyIsReDecidedFromTheProvenPagesAndBooks(t *testing.T) {
	liteHash := sha256.Sum256([]byte("s28cu-lite-key"))
	lite := liteIdentityFor(liteHash[:20])
	c := &ProvenRolesContext{Subject: Subject{Actor: "acc://alice.acme"},
		ProvenPages: map[string]KeyPageEntries{
			"acc://alice.acme/book/1":     {},
			"acc://team.acme/book/1":      {Delegates: []string{"acc://alice.acme/book"}},
			"acc://alice.acme/sub/book/1": {},
			"acc://vault.acme/book/1":     {Delegates: []string{"acc://alice.acme/sub/book"}},
			"acc://ops.acme/book/1":       {KeyHashes: [][]byte{liteHash[:]}, Delegates: []string{"acc://bob.acme"}},
		},
		ProvenBooks: map[string]uint64{"acc://ops.acme/book": 1}}
	want := func(args []string, v float64) {
		t.Helper()
		got, err := c.ResolveOperand(OpActorHasKey, args)
		if err != nil || got != TruthOperand(v == 1) {
			t.Fatalf("actor::has_key%v = %v, %v; want %v", args, got, err, v)
		}
	}
	want([]string{"acc://Alice.acme/book/1"}, 1)                   // a page of the actor's own key book
	want([]string{"acc://team.acme/book/1"}, 1)                    // the actor's own key book is a delegate
	want([]string{"acc://alice.acme/book/1", "acc://bob.acme"}, 0) // another identity holds no entry on alice's page
	// an exact identity match: a parent or a sub-identity is another identity (main's ruling on HoldsPage)
	want([]string{"acc://alice.acme/sub/book/1"}, 0)                         // alice does not hold her sub-identity's page
	want([]string{"acc://alice.acme/book/1", "acc://alice.acme/sub"}, 0)     // the sub-identity does not hold its parent's page
	want([]string{"acc://alice.acme/sub/book/1", "acc://alice.acme/sub"}, 1) // the sub-identity holds its own page
	want([]string{"acc://vault.acme/book/1"}, 0)                             // a delegate to the sub-identity's book is not alice's
	want([]string{"acc://vault.acme/book/1", "acc://alice.acme/sub"}, 1)     // it is the sub-identity's
	want([]string{"acc://ops.acme/book/1"}, 0)                               // (i) a proven page the actor holds no entry on
	want([]string{"acc://ops.acme/book/1", "acc://bob.acme"}, 1)             // the named identity's own URL is a delegate
	want([]string{"acc://ops.acme/book/1", "acc://" + lite}, 1)              // a lite identity's key hash is on the page
	want([]string{"acc://ops.acme/book/2"}, 0)                               // (ii) past the proven book's page count
	for _, args := range [][]string{{"acc://alice.acme/book/2"}, {"acc://nobody.acme/book/1"}} {
		if v, err := c.ResolveOperand(OpActorHasKey, args); !errors.Is(err, ErrAbsenceNotProvable) {
			t.Fatalf("actor::has_key%v of an unproven page answered %v, %v; want ErrAbsenceNotProvable", args, v, err)
		}
	}
	for _, args := range [][]string{nil, {"acc://ops.acme/book/1", "bob"}, {"acc://ops.acme/book/1", "acc://bob.acme", "x"}} {
		if v, err := c.ResolveOperand(OpActorHasKey, args); err == nil {
			t.Fatalf("actor::has_key%v answered %v", args, v)
		}
	}
	if v, err := (&ProvenRolesContext{ProvenPages: c.ProvenPages}).ResolveOperand(OpActorHasKey, []string{"acc://alice.acme/book/1"}); err == nil {
		t.Fatalf("actor::has_key with no actor answered %v", v)
	}
}

// liteIdentityFor is Accumulate's lite identity authority for a key hash prefix.
func liteIdentityFor(prefix []byte) string {
	h := hex.EncodeToString(prefix)
	sum := sha256.Sum256([]byte(h))
	return h + hex.EncodeToString(sum[28:])
}
