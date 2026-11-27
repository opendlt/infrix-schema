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
	// bundleHashLegacyVectorHex is the same bundle without its bundleHashRule: the legacy rule a bundle anchored before 28cd recomputes under.
	bundleHashLegacyVectorHex = "7f2ca5c50135c5a15ae690085360884cfdf92da0ad0e3fc54ac0055bbd968ba7"
	bundleHashVectorJSON      = `{"id":"ev-vector","type":"evidence_bundle","intentId":"intent-vector","planId":"plan-vector","outcomeId":"outcome-vector","outcomeRecordId":"outcome-vector","chain":{"intentId":"intent-vector","links":null,"stateRoot":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"chainHash":[12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12],"createdAt":"2026-11-26T12:00:00Z"},"stateRoot":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"anchorStatus":"unanchored","planContentHash":[14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14],"anchorCandidateDigest":[10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10],"level":"anchored","policyDecisions":[{"timestamp":"2026-11-26T12:00:00Z","policyType":"intent:transfer","scopeKey":"acc://a.acme","decision":"allow","ruleId":"r1","auditMsg":"","blockHeight":9}],"approvalEvidence":[{"stageId":"s1","identity":"acc://a.acme","role":"approver","planHash":[11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11],"signedAt":"2026-11-26T12:00:00Z"}],"stepOutcomes":[{"stageId":"s1","plannedGas":1000,"actualGas":1000,"gasDrift":-0.1,"status":"success","outputHash":[13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13],"ghostStatusMatch":false,"gasConsumed":900,"gasByCategory":{"compute":250,"crypto":50,"storage":600}}],"bundleHash":[66,205,16,14,35,33,114,106,172,61,236,254,58,64,132,226,86,87,216,223,57,174,158,196,26,107,207,159,14,126,254,150],"chainVerified":false,"bundleHashRule":2,"outcomeDigest":[10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10],"sealedBlockHeight":4242,"state":"created","createdAt":"2026-11-26T12:00:00Z","updatedAt":"2026-11-26T12:00:00Z"}`
	bundleHashVectorHex       = "42cd100e2321726aac3decfe3a4084e25657d8df39ae9ec41a6bcf9f0e7efe96"
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

// The legacy rule is kept, exactly, for the bundles already anchored under it; a sealed bundle relabelled legacy no longer recomputes to its
// hash; a rule no verifier defines is refused; Finalize seals a new bundle under the current rule and keeps a sealed bundle's rule.
func TestTheBundleHashRuleIsSealedAndTheLegacyRuleIsKeptExactly(t *testing.T) {
	b := loadBundleHashVector(t)
	if !b.BundleHashCoversSealedDigests() {
		t.Fatal("the vector bundle is sealed under the current rule")
	}
	legacy := loadBundleHashVector(t)
	legacy.BundleHashRule = BundleHashRuleLegacy
	lh, err := legacy.ComputeBundleHash()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(lh[:]) != bundleHashLegacyVectorHex {
		t.Fatalf("legacy BundleHash = %x, the shared vector says %s", lh, bundleHashLegacyVectorHex)
	}
	if lh == b.BundleHash {
		t.Fatal("a sealed bundle relabelled legacy kept its hash")
	}
	if legacy.BundleHashCoversSealedDigests() {
		t.Fatal("a legacy bundle reported its sealed digests covered")
	}
	// what the legacy rule leaves unsealed, stated exactly: a verifier must report it, never credit it
	legacy.OutcomeDigest[0] ^= 1
	if again, _ := legacy.ComputeBundleHash(); again != lh {
		t.Fatal("the legacy rule changed: a bundle anchored under it would no longer recompute")
	}
	for _, rule := range []int{1, 3, -1} {
		odd := loadBundleHashVector(t)
		odd.BundleHashRule = rule
		if _, err := odd.ComputeBundleHash(); err == nil {
			t.Fatalf("bundle hash rule %d was not refused", rule)
		}
	}

	fresh := loadBundleHashVector(t)
	fresh.BundleHash, fresh.BundleHashRule = [32]byte{}, BundleHashRuleLegacy
	if err := fresh.Finalize(); err != nil {
		t.Fatal(err)
	}
	if fresh.BundleHashRule != CurrentBundleHashRule || fresh.BundleHash != b.BundleHash {
		t.Fatalf("Finalize sealed rule %d hash %x, want rule %d hash %x", fresh.BundleHashRule, fresh.BundleHash, CurrentBundleHashRule, b.BundleHash)
	}
	sealedLegacy := loadBundleHashVector(t)
	sealedLegacy.BundleHash, sealedLegacy.BundleHashRule = lh, BundleHashRuleLegacy
	if err := sealedLegacy.Finalize(); err != nil {
		t.Fatal(err)
	}
	if sealedLegacy.BundleHashRule != BundleHashRuleLegacy || sealedLegacy.BundleHash != lh {
		t.Fatal("Finalize re-sealed a legacy bundle under another rule")
	}
}
