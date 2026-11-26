package evidence

import "testing"

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
