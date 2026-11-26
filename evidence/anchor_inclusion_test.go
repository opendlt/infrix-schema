// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
)

func inclusionLeaves(n int) [][32]byte {
	out := make([][32]byte, n)
	for i := range out {
		out[i] = sha256.Sum256([]byte{byte(i), 0x28, 0xbd})
	}
	return out
}

// Every leaf of every batch size proves into the root ComputeEvidenceMerkleRoot gives the anchorer, including the one-leaf batch
// a bundle anchored alone forms (its root is its own hash and its path is empty).
func TestAnchorInclusionProvesEveryLeafOfEveryBatchSize(t *testing.T) {
	for n := 1; n <= 9; n++ {
		leaves := inclusionLeaves(n)
		root := ComputeEvidenceMerkleRoot(leaves)
		for i := range leaves {
			p, err := GenerateAnchorInclusion(leaves, i)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if p.BatchRoot != root {
				t.Fatalf("n=%d i=%d: the proof names a root other than the batch root", n, i)
			}
			if err := VerifyAnchorInclusion(leaves[i], p); err != nil {
				t.Fatalf("n=%d i=%d: a real leaf did not verify: %v", n, i, err)
			}
			// the proof survives the JSON round trip a portable package puts it through
			raw, _ := json.Marshal(p)
			var back AnchorInclusionProof
			if err := json.Unmarshal(raw, &back); err != nil {
				t.Fatal(err)
			}
			if err := VerifyAnchorInclusion(leaves[i], &back); err != nil {
				t.Fatalf("n=%d i=%d: the decoded proof did not verify: %v", n, i, err)
			}
		}
	}
	one := inclusionLeaves(1)
	p, _ := GenerateAnchorInclusion(one, 0)
	if p.BatchRoot != one[0] || len(p.Path) != 0 || p.LeafCount != 1 {
		t.Fatalf("a one-leaf batch is not root=leaf with an empty path: %+v", p)
	}
}

// Bites: another leaf, a tampered sibling, a tampered root, an index past the batch, a padding index, and a path cut or stretched
// to land on another node of the tree are each refused.
func TestAnchorInclusionRefusesEveryTamper(t *testing.T) {
	leaves := inclusionLeaves(5)
	good, err := GenerateAnchorInclusion(leaves, 2)
	if err != nil {
		t.Fatal(err)
	}
	clone := func() *AnchorInclusionProof {
		c := *good
		c.Path = append([][32]byte(nil), good.Path...)
		return &c
	}
	cases := map[string]func() (leaf [32]byte, p *AnchorInclusionProof){
		"another leaf": func() ([32]byte, *AnchorInclusionProof) { return leaves[3], clone() },
		"foreign leaf": func() ([32]byte, *AnchorInclusionProof) { return sha256.Sum256([]byte("x")), clone() },
		"tampered sibling": func() ([32]byte, *AnchorInclusionProof) {
			c := clone()
			c.Path[1][0] ^= 1
			return leaves[2], c
		},
		"tampered root": func() ([32]byte, *AnchorInclusionProof) {
			c := clone()
			c.BatchRoot[31] ^= 1
			return leaves[2], c
		},
		"index past the batch": func() ([32]byte, *AnchorInclusionProof) {
			c := clone()
			c.LeafIndex = 5
			return leaves[2], c
		},
		"padding index": func() ([32]byte, *AnchorInclusionProof) {
			// leaf 4 is the last real leaf; 5..7 are its padding copies, which are not leaves of the batch
			p, _ := GenerateAnchorInclusion(leaves, 4)
			p.LeafIndex = 6
			return leaves[4], p
		},
		"cut path": func() ([32]byte, *AnchorInclusionProof) {
			c := clone()
			c.Path = c.Path[:len(c.Path)-1]
			return leaves[2], c
		},
		"stretched path": func() ([32]byte, *AnchorInclusionProof) {
			c := clone()
			c.Path = append(c.Path, [32]byte{})
			return leaves[2], c
		},
		"empty batch": func() ([32]byte, *AnchorInclusionProof) {
			c := clone()
			c.LeafCount = 0
			return leaves[2], c
		},
		"no proof": func() ([32]byte, *AnchorInclusionProof) { return leaves[2], nil },
	}
	for name, mk := range cases {
		leaf, p := mk()
		if err := VerifyAnchorInclusion(leaf, p); err == nil {
			t.Errorf("%s: the inclusion verified", name)
		}
	}
	if err := VerifyAnchorInclusion(leaves[2], good); err != nil {
		t.Fatalf("premise: the untampered proof does not verify: %v", err)
	}
}

// A signature field the node leaves empty is omitted from the bundle's JSON, so every bundle exported before the fields existed
// keeps its BundleHash; a filled field is hashed, so a signature swapped after sealing changes it.
func TestApprovalSignatureFieldsKeepOldBundleHashesAndBindNewOnes(t *testing.T) {
	old := &EvidenceBundle{IntentID: "i", PlanID: "p", ApprovalEvidence: []ApprovalEvidenceRef{{StageID: "s", Identity: "acc://a.acme", PlanHash: [32]byte{1}}}}
	raw, _ := json.Marshal(old.ApprovalEvidence)
	if want := `[{"stageId":"s","identity":"acc://a.acme","role":"","planHash":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"signedAt":"0001-01-01T00:00:00Z"}]`; string(raw) != want {
		t.Fatalf("an unsigned approval no longer encodes as it did before the signature fields:\n got  %s\n want %s", raw, want)
	}
	h1, err := old.ComputeBundleHash()
	if err != nil {
		t.Fatal(err)
	}
	signed := *old
	signed.ApprovalEvidence = []ApprovalEvidenceRef{old.ApprovalEvidence[0]}
	signed.ApprovalEvidence[0].Signature = []byte{9}
	h2, _ := signed.ComputeBundleHash()
	if h1 == h2 {
		t.Fatal("a signature on an approval is not covered by BundleHash")
	}
	signed.ApprovalEvidence[0].Signature = []byte{8}
	h3, _ := signed.ComputeBundleHash()
	if h3 == h2 {
		t.Fatal("swapping an approval signature does not change BundleHash")
	}
}
