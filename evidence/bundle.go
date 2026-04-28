// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"time"
)

// TRUTH HIERARCHY (canonical, do not reorganize without architectural review):
//
// 1. AnchoredRecord  -- L0-verified, immutable proof that an artifact was written to Accumulate.
//                       This is the highest level of truth. Verification: L0 data account query.
//
// 2. EvidenceBundle   -- Hash-chained forensic package for a governed execution.
//                       References OutcomeRecord by ID. Contains policy decisions, trust
//                       assumptions, and external proofs not in the outcome.
//                       Verification: chain hash recomputation.
//
// 3. OutcomeRecord    -- Transient execution result comparing plan vs actual.
//                       Source of truth for step outcomes, drift analysis, approval consumption.
//                       Verification: plan hash comparison.
//
// 4. AuditEvent       -- Low-level append-only operational telemetry.
//                       No semantic relationship to specific governed executions.
//                       Verification: hash-chain integrity.
//
// Data flows UPWARD: OutcomeRecord -> EvidenceBundle -> AnchoredRecord
// AuditEvents flow INDEPENDENTLY as operational telemetry.

// NOTE: the pkg/evidence package intentionally depends on no other
// Infrix packages. Upstream packages (pkg/policy, pkg/workflow,
// pkg/bridge, pkg/trust) already transitively import pkg/evidence, so
// referencing their types here would create an import cycle. To keep
// the bundle type self-contained while preserving the JSON wire format
// auditors expect, the bundle mirrors the exported fields of
// policy.DecisionProof, workflow.ApprovalRef, workflow.DriftAnalysis,
// and workflow.StepOutcome as local value types with matching JSON
// tags. Upstream collectors convert from the canonical types to these
// mirrors when building a bundle; external consumers see an identical
// JSON representation.

// DecisionProofRef is a JSON-compatible mirror of pkg/policy.DecisionProof
// held inside an EvidenceBundle to avoid an import cycle between
// pkg/evidence and pkg/policy. Fields and JSON tags match the source
// type exactly; higher layers convert between the two.
type DecisionProofRef struct {
	Timestamp   time.Time `json:"timestamp"`
	PolicyType  string    `json:"policyType"`
	ScopeKey    string    `json:"scopeKey"`
	Decision    string    `json:"decision"`
	RuleID      string    `json:"ruleId"`
	AuditMsg    string    `json:"auditMsg"`
	Actor       string    `json:"actor,omitempty"`
	BlockHeight uint64    `json:"blockHeight"`
}

// ApprovalEvidenceRef is a JSON-compatible mirror of
// pkg/workflow.ApprovalRef. See DecisionProofRef for the rationale.
type ApprovalEvidenceRef struct {
	StageID  string    `json:"stageId"`
	Identity string    `json:"identity"`
	Role     string    `json:"role"`
	PlanHash [32]byte  `json:"planHash"`
	SignedAt time.Time `json:"signedAt"`
}

// DriftAnalysisRef is a JSON-compatible mirror of
// pkg/workflow.DriftAnalysis held inside an EvidenceBundle.
type DriftAnalysisRef struct {
	ExceededThreshold bool     `json:"exceededThreshold"`
	MaxStepDrift      float64  `json:"maxStepDrift"`
	DriftingSteps     []string `json:"driftingSteps"`
	Summary           string   `json:"summary"`
	GhostDriftSummary string   `json:"ghostDriftSummary,omitempty"`
	GhostMaxDrift     float64  `json:"ghostMaxDrift"`
}

// StepOutcomeRef is a JSON-compatible mirror of pkg/workflow.StepOutcome
// restricted to the fields that are meaningful inside an evidence
// bundle. Sub-structures that themselves depend on higher-level
// packages (ShapeTransitionRef, SwarmStepOutcome, StepTrustResult) are
// intentionally omitted -- their content is preserved via the
// hash-linked chain, which is sufficient for auditor replay.
type StepOutcomeRef struct {
	StageID           string   `json:"stageId"`
	PlannedGas        uint64   `json:"plannedGas"`
	ActualGas         uint64   `json:"actualGas"`
	GasDrift          float64  `json:"gasDrift"`
	Status            string   `json:"status"`
	Error             string   `json:"error,omitempty"`
	OutputHash        [32]byte `json:"outputHash,omitempty"`
	GhostGasPredicted uint64   `json:"ghostGasPredicted,omitempty"`
	GhostGasDrift     float64  `json:"ghostGasDrift,omitempty"`
	GhostStatusMatch  bool     `json:"ghostStatusMatch"`
}

// EvidenceLevel controls the depth of evidence captured for a single
// intent execution. Callers select the level at collector construction
// time; downstream code consults it to decide whether a given artifact
// (plan, policy decision, step trace, ...) should be recorded. Auditors
// and regulators typically require at least EvidenceLevelStandard.
type EvidenceLevel string

const (
	// EvidenceLevelLight stores only the intent hash, the outcome hash,
	// and the resulting bundle hash. Intended for high-throughput
	// workloads where full replay capability is not required.
	EvidenceLevelLight EvidenceLevel = "light"

	// EvidenceLevelStandard adds the execution plan, every policy
	// decision consulted during execution, and every approval that was
	// consumed. This is the default level for governed workloads.
	EvidenceLevelStandard EvidenceLevel = "standard"

	// EvidenceLevelFull captures EvidenceLevelStandard plus per-step
	// execution traces, external proofs, and every trust profile that
	// was relied upon. Full bundles are suitable for forensic review
	// and for presenting to third-party auditors.
	EvidenceLevelFull EvidenceLevel = "full"

	// EvidenceLevelAnchored extends EvidenceLevelFull with the spec
	// §9.2.4 obligation: a non-zero anchor candidate digest MUST be
	// packaged at finalize time. Bundles at this level represent
	// artifacts whose lifecycle terminates with anchored finality —
	// settlement proofs, bridge proofs, compliance reports, forensic
	// reports — where the anchor candidate is part of the bundle's
	// immutable content rather than an opportunistic post-finalize
	// addition. EvidenceCollector.Finalize rejects an Anchored bundle
	// that lacks AnchorCandidateDigest. GAP-V4 closure (2026-04-28).
	EvidenceLevelAnchored EvidenceLevel = "anchored"
)

// ValidEvidenceLevels returns the canonical spec §9.2 four-tier list
// in strictness-ascending order. Every EvidenceLevel value referenced
// by production code MUST be a member of this set; resolvers should
// validate against IsValidEvidenceLevel before propagating an
// operator-supplied string. GAP-V4 closure (2026-04-28).
func ValidEvidenceLevels() []EvidenceLevel {
	return []EvidenceLevel{
		EvidenceLevelLight,
		EvidenceLevelStandard,
		EvidenceLevelFull,
		EvidenceLevelAnchored,
	}
}

// IsValidEvidenceLevel reports whether the supplied EvidenceLevel is a
// canonical spec §9.2 value. Empty strings and unrecognised values
// return false; callers translate that into either an error or a
// system-default depending on the call site.
func IsValidEvidenceLevel(l EvidenceLevel) bool {
	switch l {
	case EvidenceLevelLight, EvidenceLevelStandard, EvidenceLevelFull, EvidenceLevelAnchored:
		return true
	}
	return false
}

// AnchorStatus tracks the L0 anchoring lifecycle of an evidence bundle.
// Bundles begin unanchored, transition to pending when an anchor write
// is in flight, and reach anchored once an L0 acknowledgement arrives.
// Verified reflects that the anchor has been independently re-read and
// confirmed against the bundle's ChainHash.
type AnchorStatus string

const (
	AnchorStatusUnanchored AnchorStatus = "unanchored"
	AnchorStatusPending    AnchorStatus = "pending"
	AnchorStatusAnchored   AnchorStatus = "anchored"
	AnchorStatusVerified   AnchorStatus = "verified"
)

// BundleState tracks the overall lifecycle of an evidence bundle,
// independent of the anchoring workflow. A bundle moves from Created
// (immediately after Finalize) through Anchored and Verified, and may
// ultimately transition to Expired once retention policy elapses.
type BundleState string

const (
	BundleStateCreated  BundleState = "created"
	BundleStateAnchored BundleState = "anchored"
	BundleStateVerified BundleState = "verified"
	BundleStateExpired  BundleState = "expired"
)

// ExternalProofRef references a proof from an external chain or system
// that was consulted during execution. The ProofHash is the
// cryptographic digest of the original artifact (Merkle branch, ZK
// proof, validator-set snapshot, etc.) so that the bundle remains
// verifiable even if the external system is later unavailable.
type ExternalProofRef struct {
	SourceChain string   `json:"sourceChain"`
	ProofType   string   `json:"proofType"`
	ProofHash   [32]byte `json:"proofHash"`
	TxHash      string   `json:"txHash,omitempty"`
	BlockHeight uint64   `json:"blockHeight,omitempty"`
	Verified    bool     `json:"verified"`
}

// TrustAssumption records a trust profile that was relied upon during
// execution, together with the outcome of its evaluation. Auditors use
// the assumption list to understand which external systems or
// credentials were accepted on the basis of trust rather than direct
// cryptographic verification.
type TrustAssumption struct {
	ProfileID   string `json:"profileId"`
	ProfileName string `json:"profileName"`
	Evaluation  string `json:"evaluation"` // "passed", "failed", "skipped"
	Detail      string `json:"detail,omitempty"`
}

// EvidenceBundle is the complete, verifiable evidence package for a
// single intent execution. It references the hash-linked EvidenceChain,
// all policy decisions, approval evidence, trust assumptions, external
// proofs, drift analysis, and L0 anchor metadata. This is the artifact
// that enterprise auditors and regulators consume.
//
// The bundle is deliberately a plain data struct: it is produced by
// EvidenceCollector, persisted through the ObjectRegistry as a typed
// object of TypeEvidenceBundle, anchored to Accumulate, and exported
// to external consumers as JSON.
type EvidenceBundle struct {
	// Identity
	ID   string `json:"id"`
	Type string `json:"type"` // always "evidence_bundle"

	// References back to the intent lifecycle that produced this bundle.
	IntentID        string `json:"intentId"`
	PlanID          string `json:"planId,omitempty"`
	OutcomeID       string `json:"outcomeId,omitempty"`
	OutcomeRecordID string `json:"outcomeRecordId,omitempty"` // Canonical reference to OutcomeRecord (source of truth for step outcomes, drift, approvals)

	// The hash-linked evidence chain and the state root at the moment
	// the chain was finalized.
	Chain     *EvidenceChain `json:"chain"`
	StateRoot [32]byte       `json:"stateRoot"`

	// L0 anchoring metadata. Populated as the anchoring workflow
	// progresses; see AnchorStatus for the state machine.
	Anchor        AnchorStatus `json:"anchorStatus"`
	AnchorTxHash  string       `json:"anchorTxHash,omitempty"`
	AnchorBlock   uint64       `json:"anchorBlockHeight,omitempty"`
	AnchorDataIdx uint64       `json:"anchorDataIndex,omitempty"`

	// AnchorCandidateDigest is the SHA-256 the bundle commits to
	// anchor at finalize time. Required when Level == EvidenceLevelAnchored
	// (spec §9.2.4: "anchor candidate contribution + durable digest
	// packaging"). Set by the collector via SetAnchorCandidate before
	// Finalize. Zero value when the bundle is not at Anchored level.
	// GAP-V4 closure (2026-04-28).
	AnchorCandidateDigest [32]byte `json:"anchorCandidateDigest,omitempty"`

	// Evidence level controls which of the content fields below are
	// populated. Light bundles populate none of them, Standard bundles
	// populate policy decisions and approvals, Full bundles populate
	// everything including step outcomes and external proofs.
	Level EvidenceLevel `json:"level"`

	// Content populated based on Level.
	// Evidence-specific fields (NOT in OutcomeRecord):
	PolicyDecisions  []DecisionProofRef    `json:"policyDecisions,omitempty"`
	TrustAssumptions []TrustAssumption     `json:"trustAssumptions,omitempty"`
	ExternalProofs   []ExternalProofRef    `json:"externalProofs,omitempty"`

	// Deprecated: The following fields duplicate data that lives
	// authoritatively in OutcomeRecord. Use OutcomeRecordID to
	// reference the canonical source. These fields are retained for
	// backward compatibility but will be removed in a future phase.
	ApprovalEvidence []ApprovalEvidenceRef `json:"approvalEvidence,omitempty"` // Deprecated: use OutcomeRecord.ApprovalEvidence
	DriftAnalysis    *DriftAnalysisRef     `json:"driftAnalysis,omitempty"`    // Deprecated: use OutcomeRecord.DriftAnalysis
	StepOutcomes     []StepOutcomeRef      `json:"stepOutcomes,omitempty"`     // Deprecated: use OutcomeRecord.StepOutcomes

	// Gap 6B: explicit link to the AnchoredRecord produced from this bundle.
	// Populated by the anchoring workflow when the anchor is created.
	AnchorRecordID string `json:"anchorRecordId,omitempty"`

	// Verification metadata set by Finalize.
	BundleHash    [32]byte `json:"bundleHash"`
	ChainVerified bool     `json:"chainVerified"`

	// OutcomeDigest is the deterministic digest of the canonical
	// OutcomeRecord referenced by OutcomeRecordID. It is set by upstream
	// callers (the executor hook, the mediator) before Finalize so the
	// portable evidence package can carry an outcome-bound proof
	// independent of bundle internals. Zero when no outcome is bound
	// (subsystem-attributed bundles that produce their own artifact may
	// re-use BundleHash via SetOutcomeDigest at finalize time).
	OutcomeDigest [32]byte `json:"outcomeDigest"`

	// SealedBlockHeight is the L0 block height observed at the moment
	// the bundle was sealed. Required for portable packages so external
	// verifiers can place trust snapshots in time.
	SealedBlockHeight uint64 `json:"sealedBlockHeight"`

	// Lifecycle
	State     BundleState `json:"state"`
	ExpiresAt uint64      `json:"expiresAt,omitempty"` // Unix timestamp, 0 = no expiry
	CreatedAt time.Time   `json:"createdAt"`
	UpdatedAt time.Time   `json:"updatedAt"`

	// AuditEventIDs is an optional list of audit event IDs (from
	// pkg/audit) that correspond to this bundle's lifecycle events.
	// Phase G-11.13 uses this for cross-reference drill-down from the
	// evidence view into the audit log without copying any audit
	// payload into the bundle itself.
	AuditEventIDs []string `json:"auditEventIds,omitempty"`
}

// ComputeBundleHash computes the SHA256 hash of the bundle's immutable
// content fields. The hash covers: intent/plan/outcome identifiers,
// evidence level, chain hash, state root, policy decisions, approval
// evidence, trust assumptions, external proofs, drift analysis, and
// step outcomes. It deliberately excludes mutable fields (anchor
// status, bundle state, timestamps) so that re-computing the hash
// after lifecycle transitions yields the same value.
//
// The function is stable and deterministic: it writes fields in a
// fixed order and relies on Go's stable JSON encoder for nested
// structures.
func (b *EvidenceBundle) ComputeBundleHash() [32]byte {
	h := sha256.New()

	// Immutable identity.
	h.Write([]byte(b.IntentID))
	h.Write([]byte(b.PlanID))
	h.Write([]byte(b.OutcomeID))
	h.Write([]byte(b.Level))

	// Chain hash.
	if b.Chain != nil {
		h.Write(b.Chain.ChainHash[:])
	}

	// State root.
	h.Write(b.StateRoot[:])

	// Policy decisions (deterministic: marshal to JSON).
	if len(b.PolicyDecisions) > 0 {
		data, _ := json.Marshal(b.PolicyDecisions)
		h.Write(data)
	}

	// Approval evidence.
	if len(b.ApprovalEvidence) > 0 {
		data, _ := json.Marshal(b.ApprovalEvidence)
		h.Write(data)
	}

	// Trust assumptions.
	if len(b.TrustAssumptions) > 0 {
		data, _ := json.Marshal(b.TrustAssumptions)
		h.Write(data)
	}

	// External proofs.
	if len(b.ExternalProofs) > 0 {
		data, _ := json.Marshal(b.ExternalProofs)
		h.Write(data)
	}

	// Drift analysis.
	if b.DriftAnalysis != nil {
		data, _ := json.Marshal(b.DriftAnalysis)
		h.Write(data)
	}

	// Step outcomes.
	if len(b.StepOutcomes) > 0 {
		data, _ := json.Marshal(b.StepOutcomes)
		h.Write(data)
	}

	// GAP-V4 closure (spec §9.2.4): the anchor candidate digest is part
	// of the bundle's immutable content for Anchored bundles; including
	// it in the hash means an upgrade that mutates the candidate AFTER
	// finalize would invalidate the BundleHash and the chain-verifier
	// would catch the tampering.
	var zero [32]byte
	if b.AnchorCandidateDigest != zero {
		h.Write(b.AnchorCandidateDigest[:])
	}

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// SetAnchorCandidate stamps the anchor candidate digest the bundle
// commits to anchor at finalize time. Required for level=Anchored
// bundles per spec §9.2.4. Idempotent: calling with the same digest
// twice is a no-op; calling with a different digest after Finalize is
// a contract violation that callers must avoid (the BundleHash is
// already sealed).
//
// GAP-V4 closure (2026-04-28).
func (b *EvidenceBundle) SetAnchorCandidate(digest [32]byte) {
	b.AnchorCandidateDigest = digest
}

// ErrAnchoredBundleNeedsCandidate is the sentinel returned by Finalize
// when an Anchored-level bundle is sealed without an AnchorCandidateDigest
// stamped on it. Spec §9.2.4 requires the anchor candidate to be part
// of the bundle's immutable content; finalising without one would
// silently produce a degraded bundle that downstream verifiers cannot
// distinguish from a properly-anchored one. GAP-V4 closure (2026-04-28).
var ErrAnchoredBundleNeedsCandidate = newErr("evidence: level=anchored bundle requires AnchorCandidateDigest before Finalize (spec §9.2.4)")

// newErr is a tiny stringly-error constructor that avoids importing
// errors here (pkg/evidence is intentionally dependency-light).
func newErr(s string) error { return &simpleErr{s: s} }

type simpleErr struct{ s string }

func (e *simpleErr) Error() string { return e.s }

// Finalize seals the bundle for persistence and export. It computes
// the bundle hash, verifies the embedded evidence chain (recording the
// result in ChainVerified), sets Type to the canonical object type
// string, transitions the bundle into BundleStateCreated, initialises
// AnchorStatus to Unanchored when still empty, and stamps the update
// timestamp. Subsequent state transitions (anchored, verified, expired)
// are handled by the collector, anchoring workflow, and retention
// policies respectively.
//
// Finalize is idempotent: calling it multiple times yields the same
// BundleHash because ComputeBundleHash excludes mutable fields.
//
// GAP-V4 closure (2026-04-28): when Level == EvidenceLevelAnchored,
// the bundle MUST carry a non-zero AnchorCandidateDigest. Finalize
// returns ErrAnchoredBundleNeedsCandidate otherwise so the spec
// §9.2.4 obligation is enforced at sealing time, not opportunistically
// after the fact.
func (b *EvidenceBundle) Finalize() error {
	if b.Level == EvidenceLevelAnchored {
		var zero [32]byte
		if b.AnchorCandidateDigest == zero {
			return ErrAnchoredBundleNeedsCandidate
		}
	}
	b.Type = string(TypeEvidenceBundleObject)
	b.BundleHash = b.ComputeBundleHash()
	b.ChainVerified = VerifyChainIntegrity(b.Chain) == nil
	b.State = BundleStateCreated
	if b.Anchor == "" {
		b.Anchor = AnchorStatusUnanchored
	}
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now()
	}
	b.UpdatedAt = time.Now()
	return nil
}

// TypeEvidenceBundleObject is the canonical object-type string used
// when persisting EvidenceBundle values through the ObjectRegistry. It
// mirrors pkg/objects.TypeEvidenceBundle but is re-declared here so
// that pkg/evidence can stamp the Type field without importing
// pkg/objects (which would create an import cycle via pkg/workflow).
const TypeEvidenceBundleObject = "evidence_bundle"
