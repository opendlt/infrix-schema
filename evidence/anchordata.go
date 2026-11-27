// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

import (
	"bytes"
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

// THE ONE BATCH TREE (brief 28bk row 2, main's ruling "one tree everywhere"). The node's anchor writer, the record's batch proof, the
// bundle's AnchorInclusionProof and every verifier build and walk this tree, and nothing else:
//   - each leaf is domain-tagged: MerkleLeafHash(h) = SHA-256(0x00 || h);
//   - each internal node hashes its two children in sorted order under the internal domain: MerkleHashPair(a, b) = SHA-256(0x01 || min || max);
//   - the leaf layer is padded to the next power of 2 by repeating the last tagged leaf.
//
// The domain tags are core's PASS-33 closure, kept when the tree moved here: an internal node can never be presented as a leaf (its tagged
// hash is in another domain), and a one-leaf batch's root is its TAGGED leaf, never the raw value. It is bit-identical to the tree the node
// has always written to Accumulate (core pkg/merkle, which now delegates here), so every historical anchor root still verifies.
//
// WHAT THE HASH BINDS. Sorted pairs make the walk position-free: a path proves that the leaf is a member of the tree under the root at the
// path's depth, and NOT which position it holds. LeafIndex is carried for the reader and checked only for consistency with LeafCount; it is
// never claimed as verified by the hash.
const (
	// MerkleLeafDomain prefixes a leaf before hashing.
	MerkleLeafDomain byte = 0x00
	// MerkleInternalDomain prefixes an internal node's sorted pair before hashing.
	MerkleInternalDomain byte = 0x01
)

// MerkleLeafHash domain-tags a raw hash as a leaf of the one batch tree.
func MerkleLeafHash(raw [32]byte) [32]byte {
	// privacy-fence-exempt: Merkle tree leaf digest, not a cross-stream identity hash — the input bytes are already digests
	h := sha256.New()
	h.Write([]byte{MerkleLeafDomain})
	h.Write(raw[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MerkleHashPair hashes two nodes of the one batch tree in sorted order under the internal-node domain.
func MerkleHashPair(a, b [32]byte) [32]byte {
	// privacy-fence-exempt: Merkle tree inner-node digest, not a cross-stream identity hash — the input bytes are already digests
	h := sha256.New()
	h.Write([]byte{MerkleInternalDomain})
	if bytes.Compare(a[:], b[:]) < 0 {
		h.Write(a[:])
		h.Write(b[:])
	} else {
		h.Write(b[:])
		h.Write(a[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ComputeEvidenceMerkleRoot is the root of the one batch tree over hashes: the zero hash for no input, the tagged leaf for one.
func ComputeEvidenceMerkleRoot(hashes [][32]byte) [32]byte {
	root, _ := EvidenceMerkleRootWithProofs(hashes)
	return root
}

// EvidenceMerkleRootWithProofs is the root of the one batch tree over hashes and, for each leaf in order, its sibling path from the leaf
// level up. No input gives the zero root and no paths; one input gives its tagged leaf and an empty path.
func EvidenceMerkleRootWithProofs(hashes [][32]byte) ([32]byte, [][][32]byte) {
	n := len(hashes)
	if n == 0 {
		return [32]byte{}, nil
	}
	size := 1
	for size < n {
		size *= 2
	}
	current := make([][32]byte, size)
	for i := 0; i < size; i++ {
		if i < n {
			current[i] = MerkleLeafHash(hashes[i])
		} else {
			current[i] = current[n-1]
		}
	}
	layers := [][][32]byte{current}
	for len(current) > 1 {
		next := make([][32]byte, len(current)/2)
		for i := range next {
			next[i] = MerkleHashPair(current[2*i], current[2*i+1])
		}
		layers = append(layers, next)
		current = next
	}
	proofs := make([][][32]byte, n)
	for i := 0; i < n; i++ {
		path := make([][32]byte, 0, len(layers)-1)
		idx := i
		for _, layer := range layers[:len(layers)-1] {
			path = append(path, layer[idx^1])
			idx /= 2
		}
		proofs[i] = path
	}
	return current[0], proofs
}

// AnchorInclusionProof proves that one bundle hash is a leaf of the batch the node anchored (brief 28bd row 2, L2992): the leaf at
// LeafIndex of a LeafCount-leaf tree built by ComputeEvidenceMerkleRoot (the one batch tree), with Path the sibling hashes from the leaf
// up. A bundle anchored alone is a one-leaf batch: BatchRoot is its TAGGED bundle hash, MerkleLeafHash(bundleHash), LeafCount is 1 and
// Path is empty. The hash binds membership at the path's depth, not the position: LeafIndex is checked only against LeafCount.
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
	_, paths := EvidenceMerkleRootWithProofs(hashes)
	path := paths[index]
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

// VerifyAnchorInclusion recomputes the batch root from the TAGGED leaf along p.Path and reports whether it equals p.BatchRoot. The path
// must have exactly the depth of a LeafCount-leaf batch, so a proof cannot be stretched or cut to land on another node of the tree, and
// LeafIndex must be below LeafCount. What it proves is membership: sorted pairs do not bind the position, so a wrong LeafIndex with a
// valid path is judged by what the path proves, and the index is never reported as verified.
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
	computed := MerkleLeafHash(leaf)
	for _, sibling := range p.Path {
		computed = MerkleHashPair(computed, sibling)
	}
	if computed != p.BatchRoot {
		return fmt.Errorf("evidence: the bundle hash does not reach the batch root the anchor inclusion names")
	}
	return nil
}
