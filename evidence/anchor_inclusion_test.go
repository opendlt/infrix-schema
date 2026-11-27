// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

import (
	"crypto/sha256"
	"encoding/hex"
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
// a bundle anchored alone forms (its root is its TAGGED hash and its path is empty: the one batch tree, brief 28bk row 2).
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
	if p.BatchRoot != MerkleLeafHash(one[0]) || p.BatchRoot == one[0] || len(p.Path) != 0 || p.LeafCount != 1 {
		t.Fatalf("a one-leaf batch is not root=tagged leaf with an empty path: %+v", p)
	}
}

// WHAT THE HASH BINDS (brief 28bk row 2, main's condition): sorted pairs bind membership at the path's depth, not the position. An
// inclusion whose LeafIndex names another real leaf of the batch, with the leaf's valid path, is judged by what the path proves: it
// verifies as membership (no false refusal), and the doc says the index is never verified by the hash (no false position claim). An
// internal node presented as a leaf (PASS-33) and a raw one-leaf root (the untagged rule) are refused.
func TestAnchorInclusionBindsMembershipNotPosition(t *testing.T) {
	leaves := inclusionLeaves(6)
	p, err := GenerateAnchorInclusion(leaves, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, idx := range []uint64{0, 3, 5} {
		moved := *p
		moved.LeafIndex = idx
		if err := VerifyAnchorInclusion(leaves[1], &moved); err != nil {
			t.Fatalf("leaf 1's valid path with LeafIndex %d was refused (%v): the hash binds membership, so it must verify as membership", idx, err)
		}
	}
	// PASS-33 in the one tree: the parent of leaves 0 and 1 presented as a leaf at depth 2 of the same root does not verify
	parent := MerkleHashPair(MerkleLeafHash(leaves[0]), MerkleLeafHash(leaves[1]))
	q := &AnchorInclusionProof{BatchRoot: p.BatchRoot, LeafIndex: 0, LeafCount: 4, Path: p.Path[1:]}
	if err := VerifyAnchorInclusion(parent, q); err == nil {
		t.Fatal("an internal node verified as a leaf: the leaf/internal domain separation is broken")
	}
	// a one-leaf root that is the raw value (the untagged rule) is refused
	if err := VerifyAnchorInclusion(leaves[0], &AnchorInclusionProof{BatchRoot: leaves[0], LeafCount: 1, Path: [][32]byte{}}); err == nil {
		t.Fatal("a raw one-leaf root verified: the leaf is not domain-tagged")
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

// THE ONE TREE IS THE TREE THE NODE HAS ALWAYS WRITTEN (brief 28bk row 2). These roots were computed by core pkg/merkle.RootWithProofs
// before it delegated here, over the same leaves; every anchor already on Accumulate was written with that rule, so the moved tree must
// reproduce it bit for bit, or historical anchors would stop verifying.
func TestTheOneTreeReproducesTheRootsTheNodeWrote(t *testing.T) {
	want := map[int]string{
		1: "7bdfeb0592fa1353acd907e7d070aa5f640dd1f2ac24a9ae67a1cafeda70edf0",
		2: "254af1bbe25ce4f9191f17bb1f1c7d040734d0e6acf25b6c554c3f86822d5b02",
		3: "81aece92fd045e334cc368f98e28b8dad3adbcbe976473a6653ced4ec063c065",
		5: "ace2606429012534189223ee0f158d818419fdb9cf356bb4596b56b1c02070aa",
		8: "5bd574edd8894c361a12d7dbb733483fd6df353f2f506093fb323f4c8e36db8e",
	}
	for n, hexRoot := range want {
		root := ComputeEvidenceMerkleRoot(inclusionLeaves(n))
		if got := hex.EncodeToString(root[:]); got != hexRoot {
			t.Fatalf("n=%d: root %s, the node wrote %s", n, got, hexRoot)
		}
	}
	_, proofs := EvidenceMerkleRootWithProofs(inclusionLeaves(5))
	if got := hex.EncodeToString(proofs[4][2][:]); got != "fb3024edfd3c88773535d617162b89cdae50459f5e808b31119c81c4caec7903" {
		t.Fatalf("leaf 4 of 5: top sibling %s differs from the node's path", got)
	}
}
