package evidence

import (
	"encoding/json"
	"testing"
)

// An uncaptured proof is named after the seal, as the proofs it stands in for are embedded: it travels in the bundle's JSON (BundleData, which
// ExportHash covers) and leaves BundleHash unchanged.
func TestAnUncapturedProofIsNamedOutsideTheBundleHash(t *testing.T) {
	b := &EvidenceBundle{ID: "ev-i", IntentID: "i", PlanID: "p", OutcomeID: "o", Level: "standard"}
	before, err := b.ComputeBundleHash()
	if err != nil {
		t.Fatal(err)
	}
	b.UncapturedProofs = []UncapturedProof{{Kind: UncapturedGovernancePage, Subject: "acc://gov.acme/book/1", TxHash: "ab", Height: 7, Reason: "the capture window was lost"}}
	after, err := b.ComputeBundleHash()
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("naming an uncaptured proof changed BundleHash: %x -> %x", before, after)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var back EvidenceBundle
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.UncapturedProofs) != 1 || back.UncapturedProofs[0] != b.UncapturedProofs[0] {
		t.Fatalf("the uncaptured proof did not survive the bundle's JSON: %+v", back.UncapturedProofs)
	}
}
