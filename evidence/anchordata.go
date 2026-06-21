// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

import "crypto/sha256"

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
