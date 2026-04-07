// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// PortableEvidencePackage is a self-contained, verifiable evidence package
// that can be verified offline without platform access. It bundles the
// evidence bundle, plan/outcome digests, trust snapshot, inclusion proofs,
// and anchor proof into a single exportable artifact.
type PortableEvidencePackage struct {
	// Version identifies the schema version of this portable package.
	Version string `json:"version"`

	// BundleData is the serialized EvidenceBundle.
	BundleData json.RawMessage `json:"bundleData"`

	// PlanHash is the SHA-256 of the ExecutionPlan that was approved.
	PlanHash [32]byte `json:"planHash"`

	// OutcomeDigest is the SHA-256 of the OutcomeRecord.
	OutcomeDigest [32]byte `json:"outcomeDigest"`

	// TrustSnapshot captures the trust profile states at execution time.
	TrustSnapshot []TrustSnapshotEntry `json:"trustSnapshot,omitempty"`

	// InclusionProofs provides Merkle inclusion proofs for each evidence
	// chain link, enabling offline verification of chain integrity.
	InclusionProofs []MerkleInclusionProof `json:"inclusionProofs,omitempty"`

	// AnchorProof contains the L0 anchor data if the evidence was anchored.
	AnchorProof *EvidenceAnchorData `json:"anchorProof,omitempty"`

	// ExportHash is the SHA-256 of all other fields, providing package
	// integrity verification.
	ExportHash [32]byte `json:"exportHash"`

	// Signature is an optional cryptographic signature over ExportHash.
	Signature []byte `json:"signature,omitempty"`
}

// TrustSnapshotEntry captures one trust profile's state at a point in time.
type TrustSnapshotEntry struct {
	ProfileID   string `json:"profileId"`
	Status      string `json:"status"`      // active, degraded, suspended
	ProofType   string `json:"proofType"`
	Assumption  string `json:"assumption"`
	BlockHeight uint64 `json:"blockHeight"`
}

// BuildPortablePackage creates a PortableEvidencePackage from the given
// components. It computes the ExportHash from all included data.
func BuildPortablePackage(
	bundleData json.RawMessage,
	planHash [32]byte,
	outcomeDigest [32]byte,
	trustSnapshot []TrustSnapshotEntry,
	inclusionProofs []MerkleInclusionProof,
	anchorProof *EvidenceAnchorData,
) (*PortableEvidencePackage, error) {
	pkg := &PortableEvidencePackage{
		Version:         "1.0",
		BundleData:      bundleData,
		PlanHash:        planHash,
		OutcomeDigest:   outcomeDigest,
		TrustSnapshot:   trustSnapshot,
		InclusionProofs: inclusionProofs,
		AnchorProof:     anchorProof,
	}

	pkg.ExportHash = computePortableExportHash(pkg)
	return pkg, nil
}

// VerifyPortablePackage verifies the integrity of a portable evidence package.
// Returns (valid, warnings, error).
func VerifyPortablePackage(pkg *PortableEvidencePackage) (bool, []string, error) {
	if pkg == nil {
		return false, nil, fmt.Errorf("package is nil")
	}

	var warnings []string

	// 1. Verify export hash.
	computed := computePortableExportHash(pkg)
	if computed != pkg.ExportHash {
		return false, nil, fmt.Errorf("export hash mismatch: package has been tampered with")
	}

	// 2. Verify plan hash is non-zero.
	if pkg.PlanHash == [32]byte{} {
		warnings = append(warnings, "plan hash is zero")
	}

	// 3. Verify outcome digest is non-zero.
	if pkg.OutcomeDigest == [32]byte{} {
		warnings = append(warnings, "outcome digest is zero")
	}

	return true, warnings, nil
}

// computePortableExportHash computes the SHA-256 of all portable package
// fields except ExportHash and Signature.
func computePortableExportHash(pkg *PortableEvidencePackage) [32]byte {
	h := sha256.New()
	h.Write([]byte(pkg.Version))
	h.Write(pkg.BundleData)
	h.Write(pkg.PlanHash[:])
	h.Write(pkg.OutcomeDigest[:])

	for _, ts := range pkg.TrustSnapshot {
		data, _ := json.Marshal(ts)
		h.Write(data)
	}
	for _, ip := range pkg.InclusionProofs {
		data, _ := json.Marshal(ip)
		h.Write(data)
	}
	if pkg.AnchorProof != nil {
		data, _ := json.Marshal(pkg.AnchorProof)
		h.Write(data)
	}

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
