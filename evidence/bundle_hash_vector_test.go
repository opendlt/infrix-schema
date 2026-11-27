// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

// THE SHARED BundleHash VECTOR (brief 28cd, L3124).
//
// The same two literals sit in infrix-core (pkg/evidence/bundle_hash_vector_test.go) and infrix-verify
// (verifykit/bundle_hash_vector_test.go; the WASM verifier is that same body). Each repository parses the bundle with the schema it pins and
// recomputes the hash, so a pin that drifts from the rule, or a member renamed in one place, fails there. The bundle exercises every section,
// including a step's per-category gas and the four sealed values (outcome digest, anchor candidate digest, plan content hash, sealed block height).
const (
	bundleHashVectorJSON = `{"id":"ev-vector","type":"evidence_bundle","intentId":"intent-vector","planId":"plan-vector","outcomeId":"outcome-vector","outcomeRecordId":"outcome-vector","chain":{"intentId":"intent-vector","links":null,"stateRoot":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"chainHash":[12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12],"createdAt":"2026-11-26T12:00:00Z"},"stateRoot":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"anchorStatus":"unanchored","planContentHash":[14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14],"anchorCandidateDigest":[10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10],"level":"anchored","policyDecisions":[{"timestamp":"2026-11-26T12:00:00Z","policyType":"intent:transfer","scopeKey":"acc://a.acme","decision":"allow","ruleId":"r1","auditMsg":"","blockHeight":9}],"approvalEvidence":[{"stageId":"s1","identity":"acc://a.acme","role":"approver","planHash":[11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11],"signedAt":"2026-11-26T12:00:00Z"}],"stepOutcomes":[{"stageId":"s1","plannedGas":1000,"actualGas":1000,"gasDrift":-0.1,"status":"success","outputHash":[13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13],"ghostStatusMatch":false,"gasConsumed":900,"gasByCategory":{"compute":250,"crypto":50,"storage":600}}],"bundleHash":[103,115,162,217,99,76,171,206,231,169,61,86,42,203,244,12,12,117,134,110,149,181,129,163,220,126,241,171,218,239,177,44],"chainVerified":false,"outcomeDigest":[10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10],"sealedBlockHeight":4242,"state":"created","createdAt":"2026-11-26T12:00:00Z","updatedAt":"2026-11-26T12:00:00Z"}`
	bundleHashVectorHex  = "6773a2d9634cabcee7a93d562acbf40c0c75866e95b581a3dc7ef1abdaefb12c"
)

func loadBundleHashVector(t *testing.T) *EvidenceBundle {
	t.Helper()
	var b EvidenceBundle
	if err := json.Unmarshal([]byte(bundleHashVectorJSON), &b); err != nil {
		t.Fatal(err)
	}
	return &b
}

func TestTheSharedBundleHashVectorRecomputes(t *testing.T) {
	b := loadBundleHashVector(t)
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != bundleHashVectorJSON {
		t.Fatalf("the vector bundle does not round-trip (a member was renamed or dropped):\nin : %s\nout: %s", bundleHashVectorJSON, out)
	}
	got, err := b.ComputeBundleHash()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != bundleHashVectorHex || got != b.BundleHash {
		t.Fatalf("BundleHash = %x, the shared vector says %s (stored %x)", got, bundleHashVectorHex, b.BundleHash)
	}
}

// Every sealed value and the per-category gas are covered: each one changed (a zero outcome digest set, too) changes BundleHash.
func TestBundleHashCoversTheSealedDigestsAndTheGasCategories(t *testing.T) {
	base, _ := loadBundleHashVector(t).ComputeBundleHash()
	cases := map[string]func(b *EvidenceBundle){
		"outcome digest swapped":    func(b *EvidenceBundle) { b.OutcomeDigest[0] ^= 1 },
		"outcome digest zeroed":     func(b *EvidenceBundle) { b.OutcomeDigest = [32]byte{} },
		"anchor candidate swapped":  func(b *EvidenceBundle) { b.AnchorCandidateDigest[31] ^= 1 },
		"anchor candidate zeroed":   func(b *EvidenceBundle) { b.AnchorCandidateDigest = [32]byte{} },
		"plan content hash swapped": func(b *EvidenceBundle) { b.PlanContentHash[5] ^= 1 },
		"sealed block height moved": func(b *EvidenceBundle) { b.SealedBlockHeight++ },
		"gas moved between categories": func(b *EvidenceBundle) {
			b.StepOutcomes[0].GasByCategory["storage"]--
			b.StepOutcomes[0].GasByCategory["compute"]++
		},
		"gas category renamed": func(b *EvidenceBundle) {
			g := b.StepOutcomes[0].GasByCategory
			g["memory"] = g["crypto"]
			delete(g, "crypto")
		},
		"gas categories dropped": func(b *EvidenceBundle) { b.StepOutcomes[0].GasByCategory = nil },
		"outcome digest and candidate swapped together": func(b *EvidenceBundle) {
			b.OutcomeDigest[1] ^= 1
			b.AnchorCandidateDigest[1] ^= 1
		},
	}
	for name, mutate := range cases {
		b := loadBundleHashVector(t)
		mutate(b)
		got, err := b.ComputeBundleHash()
		if err != nil {
			t.Fatal(err)
		}
		if got == base {
			t.Errorf("%s: BundleHash did not change", name)
		}
	}

	// a digest set on a bundle sealed without one changes the hash: the section is written whether or not it is zero
	unbound := loadBundleHashVector(t)
	unbound.OutcomeDigest = [32]byte{}
	before, _ := unbound.ComputeBundleHash()
	unbound.OutcomeDigest = [32]byte{0x0a}
	if after, _ := unbound.ComputeBundleHash(); after == before {
		t.Fatal("an outcome digest added to a bundle sealed without one kept its BundleHash")
	}
}
