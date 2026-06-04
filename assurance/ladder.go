// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package assurance

import "fmt"

// ---------------------------------------------------------------------------
// Proof ladder (L1-L4): cryptographic settlement depth.
// ---------------------------------------------------------------------------

// ProofLevel classifies how deeply an artifact's commitment has been
// settled along the canonical proof chain (pkg/state -> pkg/anchor).
// The levels describe the SAME settlement chain; an artifact may enter
// at L3 (digest-anchored) without an L1/L2 storage proof, so the ladder
// reports the HIGHEST verified layer rather than requiring contiguity.
type ProofLevel uint8

const (
	// ProofLevelNone (L0) is the zero value: nothing has been proven.
	ProofLevelNone ProofLevel = iota
	// ProofLevelStorageInclusion (L1): a storage key is included in its
	// contract storage root.
	ProofLevelStorageInclusion
	// ProofLevelAccountInclusion (L2): the storage root is included in
	// the global/account root and the account leaf embeds that storage
	// root (cross-binding).
	ProofLevelAccountInclusion
	// ProofLevelBatchInclusion (L3): the artifact hash is a member of an
	// anchored batch Merkle root.
	ProofLevelBatchInclusion
	// ProofLevelL0Settlement (L4): the batch root is confirmed in an
	// Accumulate L0 transaction.
	ProofLevelL0Settlement
)

// String returns the canonical "L<n>" identifier.
func (p ProofLevel) String() string {
	switch p {
	case ProofLevelNone:
		return "L0"
	case ProofLevelStorageInclusion:
		return "L1"
	case ProofLevelAccountInclusion:
		return "L2"
	case ProofLevelBatchInclusion:
		return "L3"
	case ProofLevelL0Settlement:
		return "L4"
	default:
		return fmt.Sprintf("ProofLevel(%d)", uint8(p))
	}
}

// Label returns a human-readable description of the proof level.
func (p ProofLevel) Label() string {
	switch p {
	case ProofLevelNone:
		return "none"
	case ProofLevelStorageInclusion:
		return "storage inclusion"
	case ProofLevelAccountInclusion:
		return "account inclusion"
	case ProofLevelBatchInclusion:
		return "batch inclusion"
	case ProofLevelL0Settlement:
		return "L0 settlement"
	default:
		return "unknown"
	}
}

// Valid reports whether p is a defined proof level.
func (p ProofLevel) Valid() bool { return p <= ProofLevelL0Settlement }

// ValidProofLevels returns every defined proof level in ascending order.
func ValidProofLevels() []ProofLevel {
	return []ProofLevel{
		ProofLevelNone,
		ProofLevelStorageInclusion,
		ProofLevelAccountInclusion,
		ProofLevelBatchInclusion,
		ProofLevelL0Settlement,
	}
}

// ---------------------------------------------------------------------------
// Governance ladder (G0-G2): governance assurance.
// ---------------------------------------------------------------------------

// GovernanceLevel classifies how strongly an operation was governed. It
// attests over the outputs of the canonical policy / approval /
// credential verifiers (see GovernanceFacts).
type GovernanceLevel uint8

const (
	// GovernanceLevelUngoverned is the zero value: no policy decision, or
	// policy denied. Below G0.
	GovernanceLevelUngoverned GovernanceLevel = iota
	// GovernanceLevelPolicyPassed (G0): policy was evaluated and allowed.
	GovernanceLevelPolicyPassed
	// GovernanceLevelThresholdApproved (G1): G0 plus an M-of-N threshold
	// met by signed approval envelopes bound to the current plan hash.
	GovernanceLevelThresholdApproved
	// GovernanceLevelCredentialedAnchored (G2): G1 plus a ZK/credential
	// predicate verified and anchored evidence.
	GovernanceLevelCredentialedAnchored
)

// String returns the canonical "G<n>" identifier (or "ungoverned").
func (g GovernanceLevel) String() string {
	switch g {
	case GovernanceLevelUngoverned:
		return "ungoverned"
	case GovernanceLevelPolicyPassed:
		return "G0"
	case GovernanceLevelThresholdApproved:
		return "G1"
	case GovernanceLevelCredentialedAnchored:
		return "G2"
	default:
		return fmt.Sprintf("GovernanceLevel(%d)", uint8(g))
	}
}

// Label returns a human-readable description of the governance level.
func (g GovernanceLevel) Label() string {
	switch g {
	case GovernanceLevelUngoverned:
		return "ungoverned"
	case GovernanceLevelPolicyPassed:
		return "policy passed"
	case GovernanceLevelThresholdApproved:
		return "threshold approved"
	case GovernanceLevelCredentialedAnchored:
		return "credentialed and anchored"
	default:
		return "unknown"
	}
}

// Valid reports whether g is a defined governance level.
func (g GovernanceLevel) Valid() bool { return g <= GovernanceLevelCredentialedAnchored }

// ValidGovernanceLevels returns every defined governance level in
// ascending order.
func ValidGovernanceLevels() []GovernanceLevel {
	return []GovernanceLevel{
		GovernanceLevelUngoverned,
		GovernanceLevelPolicyPassed,
		GovernanceLevelThresholdApproved,
		GovernanceLevelCredentialedAnchored,
	}
}

// ---------------------------------------------------------------------------
// IU assurance class (the price face).
// ---------------------------------------------------------------------------

// IUAssuranceClass is the deterministic, monotone projection of
// (ProofLevel, GovernanceLevel, regulatedRetention) onto the SaaS
// billing ladder. Multipliers match the token/SaaS economy doc.
type IUAssuranceClass uint8

const (
	// IUClassSandbox (0.25x): nothing anchored, ungoverned (dev/sim).
	IUClassSandbox IUAssuranceClass = iota
	// IUClassStandard (1.0x): governed or state-proven, not batch-anchored.
	IUClassStandard
	// IUClassAnchored (2.0x): batch-anchored (>=L3).
	IUClassAnchored
	// IUClassCrossDomain (4.0x): L0-settled and threshold-approved.
	IUClassCrossDomain
	// IUClassHighAssurance (8.0x): L4 with credentialed+anchored governance.
	IUClassHighAssurance
	// IUClassRegulated (12.0x): L4 + G2 + regulated retention/audit.
	IUClassRegulated
)

// String returns the canonical class identifier.
func (c IUAssuranceClass) String() string {
	switch c {
	case IUClassSandbox:
		return "sandbox"
	case IUClassStandard:
		return "standard"
	case IUClassAnchored:
		return "anchored"
	case IUClassCrossDomain:
		return "cross_domain"
	case IUClassHighAssurance:
		return "high_assurance"
	case IUClassRegulated:
		return "regulated"
	default:
		return fmt.Sprintf("IUAssuranceClass(%d)", uint8(c))
	}
}

// Multiplier returns the IU billing multiplier for the class.
func (c IUAssuranceClass) Multiplier() float64 {
	switch c {
	case IUClassSandbox:
		return 0.25
	case IUClassStandard:
		return 1.0
	case IUClassAnchored:
		return 2.0
	case IUClassCrossDomain:
		return 4.0
	case IUClassHighAssurance:
		return 8.0
	case IUClassRegulated:
		return 12.0
	default:
		return 0
	}
}

// Valid reports whether c is a defined assurance class.
func (c IUAssuranceClass) Valid() bool { return c <= IUClassRegulated }

// ValidIUAssuranceClasses returns every defined class in ascending order.
func ValidIUAssuranceClasses() []IUAssuranceClass {
	return []IUAssuranceClass{
		IUClassSandbox,
		IUClassStandard,
		IUClassAnchored,
		IUClassCrossDomain,
		IUClassHighAssurance,
		IUClassRegulated,
	}
}

// ClassFor projects a (proof level, governance level, regulated) triple
// onto the IU assurance class. The mapping is TOTAL (defined for every
// input) and MONOTONE (raising any axis never lowers the class). Both
// properties are fenced in ladder_fence_test.go.
//
// The cascade is highest-match-wins:
//
//   - L4 + G2 + regulated                 -> Regulated      (12x)
//   - L4 + G2                              -> HighAssurance  ( 8x)
//   - L4 + G1                              -> CrossDomain    ( 4x)
//   - >= L3 (batch-anchored)               -> Anchored       ( 2x)
//   - governed (>=G0) or state-proven(>=L1)-> Standard       ( 1x)
//   - otherwise                            -> Sandbox        (0.25x)
func ClassFor(p ProofLevel, g GovernanceLevel, regulated bool) IUAssuranceClass {
	switch {
	case p >= ProofLevelL0Settlement && g >= GovernanceLevelCredentialedAnchored && regulated:
		return IUClassRegulated
	case p >= ProofLevelL0Settlement && g >= GovernanceLevelCredentialedAnchored:
		return IUClassHighAssurance
	case p >= ProofLevelL0Settlement && g >= GovernanceLevelThresholdApproved:
		return IUClassCrossDomain
	case p >= ProofLevelBatchInclusion:
		return IUClassAnchored
	case g >= GovernanceLevelPolicyPassed || p >= ProofLevelStorageInclusion:
		return IUClassStandard
	default:
		return IUClassSandbox
	}
}

// ---------------------------------------------------------------------------
// Sealed verdict.
// ---------------------------------------------------------------------------

// verdictSeal is the zero-size unexported token that makes composite-
// literal construction of Verdict outside this package a compile error.
// Same discipline as state.ConfirmedTxReceipt and spine.WriteToken.
type verdictSeal struct{}

// Verdict is the sealed assurance classification of a single governed
// operation. It can only be minted by Verifier.Attest. Accessors expose
// the proof level, governance level, IU class/multiplier, the "L<n>/G<n>"
// tier string, and the underlying proof evidence.
type Verdict struct {
	proof     ProofLevel
	gov       GovernanceLevel
	regulated bool
	evidence  ProofVerification
	seal      verdictSeal
}

// ProofLevel returns the highest verified proof level.
func (v Verdict) ProofLevel() ProofLevel { return v.proof }

// GovernanceLevel returns the classified governance level.
func (v Verdict) GovernanceLevel() GovernanceLevel { return v.gov }

// Regulated reports whether the regulated retention/audit facet applied.
func (v Verdict) Regulated() bool { return v.regulated }

// IUClass returns the IU assurance class this verdict bills at.
func (v Verdict) IUClass() IUAssuranceClass { return ClassFor(v.proof, v.gov, v.regulated) }

// IUMultiplier returns the IU billing multiplier for this verdict.
func (v Verdict) IUMultiplier() float64 { return v.IUClass().Multiplier() }

// Tier returns the canonical "L<n>/G<n>" tier string, e.g. "L4/G2".
func (v Verdict) Tier() string { return v.proof.String() + "/" + v.gov.String() }

// ProofEvidence returns the per-layer verification detail behind the
// proof level.
func (v Verdict) ProofEvidence() ProofVerification { return v.evidence }

// IsZero reports whether v is the zero verdict (L0 / ungoverned).
func (v Verdict) IsZero() bool {
	return v.proof == ProofLevelNone &&
		v.gov == GovernanceLevelUngoverned &&
		!v.regulated
}
