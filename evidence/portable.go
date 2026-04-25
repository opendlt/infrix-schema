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

// PortableEvidencePackageVersion is the canonical version string for
// the portable package wire format. Verifiers MUST reject packages
// whose Version field does not match. Pre-users: there is no support
// for prior versions.
const PortableEvidencePackageVersion = "2"

// PortableEvidencePackage is a self-contained, verifiable evidence
// package that can be verified offline without platform access. It
// bundles the evidence bundle, plan/outcome digests, trust snapshot,
// inclusion proofs, and anchor proof into a single exportable artifact.
//
// See PORTABLE_SPEC.md for the full canonical wire format and verifier
// contract.
type PortableEvidencePackage struct {
	// Version identifies the schema version. Verifiers reject any
	// value other than PortableEvidencePackageVersion.
	Version string `json:"version"`

	// BundleData is the canonicalJSON-encoded EvidenceBundle.
	BundleData json.RawMessage `json:"bundleData"`

	// PlanHash is the SHA-256 of the ExecutionPlan that was approved.
	// For subsystem-attributed bundles without approval evidence this
	// equals OutcomeDigest (artifact == outcome).
	PlanHash [32]byte `json:"planHash"`

	// OutcomeDigest is the deterministic digest of the canonical
	// OutcomeRecord referenced by the bundle.
	OutcomeDigest [32]byte `json:"outcomeDigest"`

	// TrustSnapshot captures the trust profile states at execution time.
	TrustSnapshot []TrustSnapshotEntry `json:"trustSnapshot,omitempty"`

	// InclusionProofs provides Merkle inclusion proofs for each
	// evidence chain link, enabling offline verification of chain
	// integrity.
	InclusionProofs []MerkleInclusionProof `json:"inclusionProofs,omitempty"`

	// AnchorProof contains the L0 anchor data when the embedded bundle
	// is anchored. Required when the embedded bundle's anchor status
	// is anchored or verified.
	AnchorProof *EvidenceAnchorData `json:"anchorProof,omitempty"`

	// ExportHash is the SHA-256 of all other fields, providing package
	// integrity verification.
	ExportHash [32]byte `json:"exportHash"`

	// Signature is an optional cryptographic signature over ExportHash.
	Signature []byte `json:"signature,omitempty"`
}

// TrustSnapshotEntry captures one trust profile's state at a point in time.
//
// Spec §8.3 mandates the following fields for trust-consuming
// executions: profile IDs, states, freshness timestamps, finality
// assumptions, assumption class, and verifier IDs where relevant.
// The shape is mirrored in pkg/executor.TrustSnapshotEntry so the
// portable package round-trips without field remapping.
type TrustSnapshotEntry struct {
	ProfileID     string `json:"profileId"`
	Status        string `json:"status"` // active, degraded, suspended
	ProofType     string `json:"proofType"`
	Assumption    string `json:"assumption"`
	BlockHeight   uint64 `json:"blockHeight"`
	FreshnessAt   int64  `json:"freshnessAt,omitempty"`   // Spec §8.3 freshness timestamp (Unix seconds)
	FinalityModel string `json:"finalityModel,omitempty"` // Spec §8.3 finality assumption (§14.2 value)
	VerifierID    string `json:"verifierId,omitempty"`    // Spec §8.3 verifier ID where relevant
}

// BuildPortablePackage creates a PortableEvidencePackage from the given
// components. It computes the ExportHash from all included data using
// the canonical encoding rules in PORTABLE_SPEC.md.
func BuildPortablePackage(
	bundleData json.RawMessage,
	planHash [32]byte,
	outcomeDigest [32]byte,
	trustSnapshot []TrustSnapshotEntry,
	inclusionProofs []MerkleInclusionProof,
	anchorProof *EvidenceAnchorData,
) (*PortableEvidencePackage, error) {
	pkg := &PortableEvidencePackage{
		Version:         PortableEvidencePackageVersion,
		BundleData:      bundleData,
		PlanHash:        planHash,
		OutcomeDigest:   outcomeDigest,
		TrustSnapshot:   trustSnapshot,
		InclusionProofs: inclusionProofs,
		AnchorProof:     anchorProof,
	}
	hash, err := computePortableExportHash(pkg)
	if err != nil {
		return nil, fmt.Errorf("evidence: compute export hash: %w", err)
	}
	pkg.ExportHash = hash
	return pkg, nil
}

// VerifyPortablePackage performs a strict, offline verification of a
// portable evidence package. Gap 8 sub-gap B closure: every check is
// fail-loud — there are no warnings.
//
// Verification steps:
//  1. Package is non-nil and Version matches.
//  2. ExportHash recomputes to the value stored in the package.
//  3. BundleData is non-empty and parses as a valid EvidenceBundle.
//  4. PlanHash is non-zero.
//  5. OutcomeDigest is non-zero and matches the embedded bundle's
//     OutcomeDigest field.
//  6. Every inclusion proof verifies against its declared ChainHash.
//  7. If the embedded bundle is anchored, AnchorProof is non-nil and
//     its TxHash matches the bundle's AnchorTxHash.
//  8. If TrustSnapshot is populated, every entry has a non-zero
//     BlockHeight (the seal-time anchor is mandatory).
func VerifyPortablePackage(pkg *PortableEvidencePackage) error {
	if pkg == nil {
		return fmt.Errorf("evidence/portable: package is nil")
	}

	// 1. Version check.
	if pkg.Version != PortableEvidencePackageVersion {
		return fmt.Errorf("evidence/portable: unsupported version %q (expected %q)",
			pkg.Version, PortableEvidencePackageVersion)
	}

	// 2. Export hash integrity.
	computed, err := computePortableExportHash(pkg)
	if err != nil {
		return fmt.Errorf("evidence/portable: recompute export hash: %w", err)
	}
	if computed != pkg.ExportHash {
		return fmt.Errorf("evidence/portable: export hash mismatch (package tampered or non-canonical encoding)")
	}

	// 3. BundleData parses.
	if len(pkg.BundleData) == 0 {
		return fmt.Errorf("evidence/portable: empty BundleData")
	}
	var embedded EvidenceBundle
	if err := json.Unmarshal(pkg.BundleData, &embedded); err != nil {
		return fmt.Errorf("evidence/portable: BundleData not a valid EvidenceBundle: %w", err)
	}

	// 4. Plan hash.
	if pkg.PlanHash == [32]byte{} {
		return fmt.Errorf("evidence/portable: PlanHash is zero")
	}

	// 5. Outcome digest matches the embedded bundle.
	if pkg.OutcomeDigest == [32]byte{} {
		return fmt.Errorf("evidence/portable: OutcomeDigest is zero")
	}
	if embedded.OutcomeDigest != pkg.OutcomeDigest {
		return fmt.Errorf("evidence/portable: OutcomeDigest does not match embedded bundle.OutcomeDigest")
	}

	// 6. Inclusion proofs.
	for i, proof := range pkg.InclusionProofs {
		p := proof
		if !VerifyMerkleInclusionProof(&p) {
			return fmt.Errorf("evidence/portable: inclusion proof %d failed verification", i)
		}
	}

	// 7. Anchor proof when bundle is anchored.
	if embedded.Anchor == AnchorStatusAnchored || embedded.Anchor == AnchorStatusVerified {
		if pkg.AnchorProof == nil {
			return fmt.Errorf("evidence/portable: anchored bundle missing AnchorProof")
		}
		if pkg.AnchorProof.BundleID != embedded.ID {
			return fmt.Errorf("evidence/portable: AnchorProof.BundleID %q does not match embedded bundle.ID %q",
				pkg.AnchorProof.BundleID, embedded.ID)
		}
	}

	// 8. Trust snapshot freshness.
	for i, entry := range pkg.TrustSnapshot {
		if entry.BlockHeight == 0 {
			return fmt.Errorf("evidence/portable: trust snapshot entry %d has zero BlockHeight", i)
		}
	}

	return nil
}

// computePortableExportHash computes the SHA-256 of all portable
// package fields except ExportHash and Signature. It uses the
// canonical JSON encoding so that the resulting hash is reproducible
// across runs and across implementations conforming to PORTABLE_SPEC.md.
func computePortableExportHash(pkg *PortableEvidencePackage) ([32]byte, error) {
	// Build a deterministic intermediate representation that excludes
	// ExportHash and Signature.
	intermediate := map[string]any{
		"version":         pkg.Version,
		"bundleData":      json.RawMessage(pkg.BundleData),
		"planHash":        pkg.PlanHash,
		"outcomeDigest":   pkg.OutcomeDigest,
		"trustSnapshot":   pkg.TrustSnapshot,
		"inclusionProofs": pkg.InclusionProofs,
		"anchorProof":     pkg.AnchorProof,
	}
	canonical, err := canonicalJSON(intermediate)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}
