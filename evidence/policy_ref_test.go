package evidence

import (
	"encoding/json"
	"testing"
)

// PolicyEvaluations are covered by BundleHash when present, and a bundle without them keeps the hash it always had.
func TestPolicyEvaluationsAreCoveredByBundleHash(t *testing.T) {
	b := &EvidenceBundle{IntentID: "i", PlanID: "p", Level: EvidenceLevelStandard,
		PolicyDecisions: []DecisionProofRef{{PolicyType: "intent:transfer", Decision: "allow"}}}
	before, err := b.ComputeBundleHash()
	if err != nil {
		t.Fatal(err)
	}
	b.PolicyEvaluations = []PolicyEvaluation{{PolicyType: "intent:transfer", Policy: PolicyRef{Hash: [32]byte{1}, Content: []byte(`{}`)}, Subject: PolicySubject{Actor: "a"}}}
	with, err := b.ComputeBundleHash()
	if err != nil {
		t.Fatal(err)
	}
	if with == before {
		t.Fatal("adding a policy evaluation did not change BundleHash")
	}
	b.PolicyEvaluations[0].Subject.Actor = "b"
	mutated, _ := b.ComputeBundleHash()
	if mutated == with {
		t.Fatal("changing the policy subject did not change BundleHash")
	}
	b.PolicyEvaluations = nil
	if again, _ := b.ComputeBundleHash(); again != before {
		t.Fatal("a bundle without policy evaluations changed its BundleHash")
	}
}

// A PolicyRef's content survives the bundle's canonical encoding byte for byte, so its hash still addresses it after export.
func TestPolicyRefContentSurvivesCanonicalEncoding(t *testing.T) {
	content := []byte(`{"id":"p","name":"","type":"t","version":0,"defaultEffect":"allow","rules":[]}`)
	b := &EvidenceBundle{IntentID: "i", PolicyEvaluations: []PolicyEvaluation{{PolicyType: "t", Policy: PolicyRef{Content: content}}}}
	data, err := CanonicalJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	var back EvidenceBundle
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if string(back.PolicyEvaluations[0].Policy.Content) != string(content) {
		t.Fatalf("content changed through canonical encoding: %s", back.PolicyEvaluations[0].Policy.Content)
	}
}
