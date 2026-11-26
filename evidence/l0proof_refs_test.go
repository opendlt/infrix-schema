// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

import (
	"encoding/json"
	"testing"
)

// The embedded Accumulate proofs are captured after a bundle is sealed: they leave BundleHash unchanged, and ExportHash covers every byte of them.
func TestL0ProofRefsKeepBundleHashAndBindExportHash(t *testing.T) {
	b := &EvidenceBundle{ID: "b", Type: TypeEvidenceBundleObject, IntentID: "i", Chain: &EvidenceChain{}}
	before, err := b.ComputeBundleHash()
	if err != nil {
		t.Fatal(err)
	}
	b.L0Proof = json.RawMessage(`{"incarnation":"pin:aa"}`)
	b.KeyPageProofs = []json.RawMessage{json.RawMessage(`{"page":"acc://app.acme/book/1"}`)}
	b.GovernanceExecution = json.RawMessage(`{"txHash":"00"}`)
	after, err := b.ComputeBundleHash()
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("the embedded proofs changed BundleHash; they are captured after the bundle is sealed")
	}
	export := func(bb *EvidenceBundle) [32]byte {
		data, err := json.Marshal(bb)
		if err != nil {
			t.Fatal(err)
		}
		h, err := ComputePortableExportHash(&PortableEvidencePackage{BundleData: data})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	base := export(b)
	for name, mutate := range map[string]func(*EvidenceBundle){
		"l0Proof":             func(c *EvidenceBundle) { c.L0Proof = json.RawMessage(`{"incarnation":"pin:ab"}`) },
		"keyPageProofs":       func(c *EvidenceBundle) { c.KeyPageProofs = []json.RawMessage{json.RawMessage(`{"page":"acc://app.acme/book/2"}`)} },
		"governanceExecution": func(c *EvidenceBundle) { c.GovernanceExecution = json.RawMessage(`{"txHash":"01"}`) },
	} {
		c := *b
		mutate(&c)
		if export(&c) == base {
			t.Fatalf("ExportHash does not cover %s", name)
		}
	}
}
