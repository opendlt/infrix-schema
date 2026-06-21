// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

import (
	"crypto/sha256"
	"fmt"
)

// ---------------------------------------------------------------------------
// Merkle inclusion proofs (G11-8.2)
// ---------------------------------------------------------------------------

// MerkleInclusionProof proves that a specific evidence link exists
// in the chain without revealing the full chain. Selective disclosure
// uses this to prove a policy decision or approval occurred without
// exposing the complete execution trace.
type MerkleInclusionProof struct {
	BundleID  string       `json:"bundleId"`
	LinkIndex int          `json:"linkIndex"`
	Link      EvidenceLink `json:"link"`
	Proof     [][32]byte   `json:"proof"`     // Merkle sibling hashes
	ChainHash [32]byte     `json:"chainHash"` // expected root
}

// GenerateMerkleInclusionProof generates an inclusion proof for the
// link at the given index. The proof consists of the sibling hashes
// along the path from the leaf to the root; combined with the
// bundle's stored ChainHash it lets a verifier confirm the link was
// present in the chain without seeing any other link content.
//
// Important: EvidenceChain.ChainHash is defined as
// SHA256(link1.ContentHash || link2.ContentHash || ...) -- a flat
// concatenation, not a Merkle tree. The inclusion proof produced by
// this function uses a true Merkle tree over the same content
// hashes, so its root is distinct from ChainHash. The returned proof
// carries its own `ChainHash` field set to the Merkle root so
// verifiers know exactly what to reconstruct.
func GenerateMerkleInclusionProof(bundle *EvidenceBundle, linkIndex int) (*MerkleInclusionProof, error) {
	if bundle == nil {
		return nil, fmt.Errorf("evidence: nil bundle")
	}
	if bundle.Chain == nil {
		return nil, fmt.Errorf("evidence: bundle has no chain")
	}
	if linkIndex < 0 || linkIndex >= len(bundle.Chain.Links) {
		return nil, fmt.Errorf("evidence: invalid link index %d (chain has %d links)",
			linkIndex, len(bundle.Chain.Links))
	}

	hashes := make([][32]byte, len(bundle.Chain.Links))
	for i, link := range bundle.Chain.Links {
		hashes[i] = link.ContentHash
	}

	proof := buildMerkleProof(hashes, linkIndex)
	root := ComputeEvidenceMerkleRoot(hashes)

	return &MerkleInclusionProof{
		BundleID:  bundle.ID,
		LinkIndex: linkIndex,
		Link:      bundle.Chain.Links[linkIndex],
		Proof:     proof,
		ChainHash: root,
	}, nil
}

// VerifyMerkleInclusionProof reconstructs the Merkle root from the
// proof's leaf + sibling hashes and compares it against the
// proof.ChainHash field. Returns true when the reconstructed root
// matches, false otherwise.
func VerifyMerkleInclusionProof(proof *MerkleInclusionProof) bool {
	if proof == nil {
		return false
	}
	computed := proof.Link.ContentHash
	idx := proof.LinkIndex
	for _, sibling := range proof.Proof {
		h := sha256.New()
		if idx%2 == 0 {
			h.Write(computed[:])
			h.Write(sibling[:])
		} else {
			h.Write(sibling[:])
			h.Write(computed[:])
		}
		copy(computed[:], h.Sum(nil))
		idx /= 2
	}
	return computed == proof.ChainHash
}

// buildMerkleProof constructs the sibling hashes needed to prove
// that the leaf at `index` is included in the tree built from
// `hashes`. The tree is padded to the next power of 2 by repeating
// the last leaf -- the same padding convention used by
// ComputeEvidenceMerkleRoot so the two functions always agree on
// the root.
func buildMerkleProof(hashes [][32]byte, index int) [][32]byte {
	if len(hashes) == 0 {
		return nil
	}
	n := len(hashes)
	size := 1
	for size < n {
		size *= 2
	}
	padded := make([][32]byte, size)
	copy(padded, hashes)
	for i := n; i < size; i++ {
		padded[i] = hashes[n-1]
	}

	var proof [][32]byte
	idx := index
	for size > 1 {
		if idx%2 == 0 {
			proof = append(proof, padded[idx+1])
		} else {
			proof = append(proof, padded[idx-1])
		}
		newPadded := make([][32]byte, size/2)
		for i := 0; i < size/2; i++ {
			h := sha256.New()
			h.Write(padded[i*2][:])
			h.Write(padded[i*2+1][:])
			copy(newPadded[i][:], h.Sum(nil))
		}
		padded = newPadded
		size /= 2
		idx /= 2
	}
	return proof
}
