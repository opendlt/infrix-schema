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

// EvidenceAnchorData is the per-bundle record written to the L0
// evidence data account. It intentionally contains only hashes and
// identifiers: the full bundle remains in the off-chain BundleStore,
// while L0 supplies independent tamper-evidence for the hashes.
// Privacy P4-A closure (2026-05-15): the on-disk L0 anchor format
// MUST NOT carry raw IntentID / PlanID strings — the Accumulate L0
// chain is permanently public and a raw ADI URL there is a forever-
// observable identity leak. Pre-closure the struct held bundle.IntentID
// + bundle.PlanID verbatim (and Version=1 reflects that wire shape).
// Post-closure the struct ships Version=2 with IntentIDHash + PlanIDHash
// SHA-256 prefixes under the canonical "evidence/v1:" domain — same
// hash format the REST evidence-bundle redactor (pkg/evidence/bundle_redact.go)
// emits, so a verifier holding the original IntentID can recompute
// the same hash and confirm bundle provenance without the raw URL
// ever touching the public chain.
type EvidenceAnchorData struct {
	Version    uint32   `json:"version"` // 2 for hashed-identifier release
	BundleID   string   `json:"bundleId"`
	BundleHash [32]byte `json:"bundleHash"`
	ChainHash  [32]byte `json:"chainHash"`
	StateRoot  [32]byte `json:"stateRoot"`
	// IntentIDHash is sha256("evidence/v1:intent:" + IntentID)[:16] —
	// truncated to 16 bytes (128 bits) for compactness; preimage
	// resistance under the prefix domain remains 128 bits.
	IntentIDHash [16]byte `json:"intentIdHash"`
	// PlanIDHash is sha256("evidence/v1:plan:" + PlanID)[:16]. Empty
	// (all-zero) when the bundle has no PlanID — distinguishable
	// from a real hash because the all-zero array is not a valid
	// SHA-256 output.
	PlanIDHash  [16]byte `json:"planIdHash,omitempty"`
	Level       string   `json:"level"`
	LinkCount   int      `json:"linkCount"`
	BlockHeight uint64   `json:"blockHeight"`
	Timestamp   int64    `json:"timestamp"` // unix nanos
}

// ComputeEvidenceMerkleRoot builds a binary Merkle tree over the
// provided bundle hashes and returns the root. For non-power-of-2
// inputs the last hash is repeated to pad up to the next power of 2
// -- a common, well-understood convention that keeps verification
// logic simple without introducing duplicate-input attacks because
// each leaf here is a pre-finalised bundle hash under operator
// control.
//
// The zero hash is returned for an empty input. A single-element
// input returns that element unchanged (no hashing) so a one-bundle
// "batch" retains its identity.
func ComputeEvidenceMerkleRoot(hashes [][32]byte) [32]byte {
	if len(hashes) == 0 {
		return [32]byte{}
	}
	if len(hashes) == 1 {
		return hashes[0]
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

	for size > 1 {
		for i := 0; i < size/2; i++ {
			// privacy-fence-exempt: Merkle tree inner-node digest, not a cross-stream identity hash — the input bytes are already digests
			h := sha256.New()
			h.Write(padded[i*2][:])
			h.Write(padded[i*2+1][:])
			copy(padded[i][:], h.Sum(nil))
		}
		size /= 2
	}

	return padded[0]
}

// AnchorInclusionProof proves that one bundle hash is a leaf of the batch the node anchored (brief 28bd row 2, L2992): the leaf at
// LeafIndex of a LeafCount-leaf tree built by ComputeEvidenceMerkleRoot, with Path the sibling hashes from the leaf up. A bundle
// anchored alone is a one-leaf batch: BatchRoot is its own bundle hash, LeafCount is 1 and Path is empty.
//
// It is what a verifier credits proof level L3 (batch inclusion) from, recomputed over the bundle hash it derives itself; the
// bundle's anchorStatus field, which the node sets, is never read for it.
type AnchorInclusionProof struct {
	BatchRoot [32]byte   `json:"batchRoot"`
	LeafIndex uint64     `json:"leafIndex"`
	LeafCount uint64     `json:"leafCount"`
	Path      [][32]byte `json:"path"`
}

// GenerateAnchorInclusion returns the inclusion proof of hashes[index] in the batch root ComputeEvidenceMerkleRoot(hashes).
func GenerateAnchorInclusion(hashes [][32]byte, index int) (*AnchorInclusionProof, error) {
	if len(hashes) == 0 {
		return nil, fmt.Errorf("evidence: an anchor inclusion needs at least one leaf")
	}
	if index < 0 || index >= len(hashes) {
		return nil, fmt.Errorf("evidence: anchor inclusion index %d is outside the %d-leaf batch", index, len(hashes))
	}
	path := buildMerkleProof(hashes, index)
	if path == nil {
		path = [][32]byte{}
	}
	return &AnchorInclusionProof{
		BatchRoot: ComputeEvidenceMerkleRoot(hashes),
		LeafIndex: uint64(index),
		LeafCount: uint64(len(hashes)),
		Path:      path,
	}, nil
}

// anchorInclusionDepth is the number of siblings a LeafCount-leaf batch's path carries: the depth of the tree padded to a power of 2.
func anchorInclusionDepth(leafCount uint64) int {
	depth := 0
	for size := uint64(1); size < leafCount; size *= 2 {
		depth++
	}
	return depth
}

// VerifyAnchorInclusion recomputes the batch root from leaf along p.Path and reports whether it equals p.BatchRoot. The index must
// name a real leaf (not a padding copy) and the path must have exactly the batch's depth, so a proof cannot be stretched or cut to
// land on another node of the tree.
func VerifyAnchorInclusion(leaf [32]byte, p *AnchorInclusionProof) error {
	if p == nil {
		return fmt.Errorf("evidence: no anchor inclusion proof")
	}
	if p.LeafCount == 0 {
		return fmt.Errorf("evidence: anchor inclusion names an empty batch")
	}
	if p.LeafIndex >= p.LeafCount {
		return fmt.Errorf("evidence: anchor inclusion leaf %d is outside the %d-leaf batch", p.LeafIndex, p.LeafCount)
	}
	if want := anchorInclusionDepth(p.LeafCount); len(p.Path) != want {
		return fmt.Errorf("evidence: anchor inclusion path has %d sibling(s), a %d-leaf batch has depth %d", len(p.Path), p.LeafCount, want)
	}
	computed := leaf
	idx := p.LeafIndex
	for _, sibling := range p.Path {
		// privacy-fence-exempt: Merkle tree inner-node digest, not a cross-stream identity hash — the input bytes are already digests
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
	if computed != p.BatchRoot {
		return fmt.Errorf("evidence: the bundle hash does not reach the batch root the anchor inclusion names")
	}
	return nil
}
