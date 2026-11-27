// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
)

// PolicyRef is a content-addressed policy: Content is the canonical policy document (infrix-schema policyeval.EncodeDocument) and Hash is
// its SHA-256 (policyeval.ContentHash). A verifier refuses a PolicyRef whose content does not hash to Hash (native proof plan BD-06).
//
// Content is bytes (base64 in JSON), never embedded JSON: the bundle's canonical encoding re-encodes embedded JSON (it sorts object keys),
// which would change the bytes the hash addresses.
type PolicyRef struct {
	Hash    [32]byte `json:"hash"`
	Content []byte   `json:"content"`
}

// PolicySubject is what a goal policy was decided over at intent admission, the fields of policyeval.Subject (this package stays
// stdlib-only, so it mirrors them). Amount is absent when the goal stated none.
type PolicySubject struct {
	Actor       string   `json:"actor"`
	Contract    string   `json:"contract,omitempty"`
	Function    string   `json:"function,omitempty"`
	BlockHeight uint64   `json:"blockHeight"`
	Amount      *float64 `json:"amount,omitempty"`
}

// PolicyEvaluation is one decision a plan was governed under, in re-evaluable form: the policy type and scope it was decided at, the
// content-addressed policy in force, and the subject. It carries no decision: the verifier decides.
type PolicyEvaluation struct {
	PolicyType string        `json:"policyType"`
	ScopeKey   string        `json:"scopeKey,omitempty"`
	Policy     PolicyRef     `json:"policy"`
	Subject    PolicySubject `json:"subject"`
}

// PlanBindingTag domain-separates a plan hash that commits to the policy evaluations its plan was governed under (brief 28bu row 2, the
// L3008 (b) ruling): PlanHash = SHA-256(PlanBindingTag || PlanContentHash || PolicySubjectsDigest(evaluations)).
const PlanBindingTag = "infrix:plan-policy-binding:v1"

// PolicySubjectsDigest is the SHA-256 of the evaluations a plan was governed under, in order: each one's policy type, scope key, policy
// content hash and the whole subject (actor, contract, function, height, amount), every field length-prefixed so no two lists collide.
func PolicySubjectsDigest(evals []PolicyEvaluation) [32]byte {
	h := sha256.New()
	field := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	num := func(v uint64) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], v)
		field(n[:])
	}
	num(uint64(len(evals)))
	for _, ev := range evals {
		field([]byte(ev.PolicyType))
		field([]byte(ev.ScopeKey))
		field(ev.Policy.Hash[:])
		field([]byte(ev.Subject.Actor))
		field([]byte(ev.Subject.Contract))
		field([]byte(ev.Subject.Function))
		num(ev.Subject.BlockHeight)
		if ev.Subject.Amount == nil {
			field(nil)
		} else {
			num(math.Float64bits(*ev.Subject.Amount))
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// BindPlanHash is the plan hash approvers sign for a plan whose content hashes to content and which was governed under evals: with no
// evaluation it is content itself; with any, SHA-256(PlanBindingTag || content || PolicySubjectsDigest(evals)), so changing a subject (who,
// which contract and function, at what height, for what amount), a policy or its order changes the hash every approval signed.
func BindPlanHash(content [32]byte, evals []PolicyEvaluation) [32]byte {
	if len(evals) == 0 {
		return content
	}
	d := PolicySubjectsDigest(evals)
	h := sha256.New()
	h.Write([]byte(PlanBindingTag))
	h.Write(content[:])
	h.Write(d[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
