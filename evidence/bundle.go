// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
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
//
// The signature fields (brief 28bd row 1, L2992) carry the approval exactly as the node's approval store verified it, so a verifier
// can check it itself instead of crediting an identity string: SignedPreimage is the canonical approval preimage the signer signed
// (domain "infrix/approval-signature/v2", the encoding pkg/workflow.TypedApproval.SigningPreimage writes), Signature and PublicKey
// are the signature and the key that made it, SigType names the scheme (one of the ApprovalSigType constants), SignerPage is the
// Accumulate key page the approval names, and SignatureMetadataHash is the Accumulate signature-metadata hash an accumulate-* type
// signs beside the approval hash. A verifier reads the plan hash, stage, identity, role, key page and key from the PREIMAGE and
// requires them to equal these fields; nothing here is credited because the node wrote it.
//
// Every signature field is omitted when empty, so a bundle exported before they existed (or an approval the store accepted
// unsigned, test/devnet only) keeps its BundleHash; such an approval proves nothing and caps governance at G0.
type ApprovalEvidenceRef struct {
	StageID  string    `json:"stageId"`
	Identity string    `json:"identity"`
	Role     string    `json:"role"`
	PlanHash [32]byte  `json:"planHash"`
	SignedAt time.Time `json:"signedAt"`

	Signature             []byte `json:"signature,omitempty"`
	PublicKey             []byte `json:"publicKey,omitempty"`
	SigType               string `json:"sigType,omitempty"`
	SignerPage            string `json:"signerPage,omitempty"`
	SignedPreimage        []byte `json:"signedPreimage,omitempty"`
	SignatureMetadataHash []byte `json:"signatureMetadataHash,omitempty"`
}

// The approval signature schemes an ApprovalEvidenceRef can declare.
//
//   - ApprovalSigTypeInfrixEd25519: the original form, a bare Ed25519 signature over SignedPreimage.
//   - ApprovalSigTypeAccumulatePrefix + an Accumulate user-signature type name (ed25519, btc, eth, legacyED25519, rcd1, btcLegacy,
//     rsaSha256, ecdsaSha256): the network's own signature, made over sha256(SignatureMetadataHash || sha256(SignedPreimage)) the way
//     Accumulate's executor verifies a user signature.
const (
	ApprovalSigTypeInfrixEd25519    = "infrix-ed25519"
	ApprovalSigTypeAccumulatePrefix = "accumulate-"
)

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

	// GasConsumed is what the step's work used when that differs from ActualGas (a contract call's ActualGas is the limit it reserved);
	// GasByCategory is GasConsumed split by meter category (compute, storage, memory, host, crypto, ..., "uncategorized"), summing to it.
	// Both mirror pkg/workflow.StepOutcome (brief 28bz, L3087), are omitted when the step recorded none, and are covered by BundleHash
	// through the step-outcome section (brief 28cd, L3124).
	GasConsumed   uint64            `json:"gasConsumed,omitempty"`
	GasByCategory map[string]uint64 `json:"gasByCategory,omitempty"`
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
	// Account and L0Proof are the EMBEDDED confirmation of the proof (brief 28bk row 3, main's ruling (a)): the Accumulate data account the
	// WriteData holding ProofHash as one whole data item was written to, and the infrix-verify l0proof chain of that transaction to a certified
	// Directory header. A verifier checks the chain against ITS OWN pin (a compiled network pin or one the relying party passes), never the
	// bundle's, and credits the confirmation from it offline (source embedded-proof); a live re-read stays the other route. Raw bytes, so the
	// bundle's canonical encoding never re-encodes the chain the hash covers; both omitted when empty, so every earlier bundle keeps its hash.
	Account string `json:"account,omitempty"`
	L0Proof []byte `json:"l0Proof,omitempty"`
}

// UncapturedProof names one proof the node owed a bundle and could not capture: its Kind (UncapturedGovernancePage), the Subject it would prove
// (the page URL), the Accumulate transaction it belongs to, the block the proof had to be taken at when known, and why it was not captured.
type UncapturedProof struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	TxHash  string `json:"txHash,omitempty"`
	Height  uint64 `json:"height,omitempty"`
	Reason  string `json:"reason"`
}

// UncapturedGovernancePage is the Kind of a governance page proof at the block that executed the approval, lost with its capture window.
const UncapturedGovernancePage = "governance_page"

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

	// AnchorInclusion proves this bundle's hash is a leaf of the batch root the anchor transaction wrote (a one-leaf batch for a
	// bundle anchored alone). Set by the anchorer with the other anchor metadata; like them it is not part of BundleHash, and like
	// them it travels in a portable package's BundleData, which ExportHash covers. Proof level L3 is credited from it, never from
	// Anchor (brief 28bd row 2).
	AnchorInclusion *AnchorInclusionProof `json:"anchorInclusion,omitempty"`

	// StorageProofs and AccountProofs are the state proofs of the keys the bundle claims (state_inclusion.go): each key in its contract
	// root (L1) and each contract root in StateRoot (L2). They are proofs ABOUT StateRoot, which BundleHash covers, so they are not hashed
	// into BundleHash; they travel in BundleData, which ExportHash covers.
	StorageProofs []StorageInclusionProof `json:"storageProofs,omitempty"`
	AccountProofs []AccountInclusionProof `json:"accountProofs,omitempty"`
	// RoleRegistryProof proves the global roles of every actor whose policy evaluation the bundle carries, against StateRoot
	// (role_registry.go; infrix-core L3112), so a verifier re-runs a policy that reads actor::role. Like StorageProofs it is a proof ABOUT
	// StateRoot, which BundleHash covers, so it is not hashed into BundleHash; it travels in BundleData, which ExportHash covers.
	RoleRegistryProof *RoleRegistryProof `json:"roleRegistryProof,omitempty"`

	// L0Proof, KeyPageProofs and GovernanceExecution are the Accumulate proofs the node's capture service embeds after Directory certification (the native
	// proof plan, phases 5 and 7; l0proof_refs.go). Like AnchorInclusion they are captured after the bundle is sealed, so they are not part of BundleHash;
	// they travel in BundleData, which ExportHash covers. A verifier checks each against ITS OWN pinned network incarnation; nothing here selects a pin.
	L0Proof             json.RawMessage   `json:"l0Proof,omitempty"`
	KeyPageProofs       []json.RawMessage `json:"keyPageProofs,omitempty"`
	GovernanceExecution json.RawMessage   `json:"governanceExecution,omitempty"`
	// OperandPageProofs are infrix-verify govproof.KeyPageProof values for the key pages the bundle's policy evaluations read through
	// actor::has_key (infrix-core L3196): each proves its page exists at a Directory-certified block under the pin, so the verifier re-decides
	// actor::has_key through the node's own body (policyeval.ResolveActorHasKey over ProvenRolesContext.ProvenPages). They are apart from
	// KeyPageProofs, which prove only the pages approvals name. An account's absence has no proof (Accumulate's receipts prove membership only),
	// so a "false" answer carries none and stays unproven. Captured after the seal; not part of BundleHash; travels in BundleData.
	OperandPageProofs []json.RawMessage `json:"operandPageProofs,omitempty"`

	// UncapturedProofs names every embedded proof the node owed this bundle and could not capture (main's ruling 2026-11-26 on the governance
	// capture window): an approval Accumulate executed whose page proof at the executing block was lost to a node crash on a network that serves
	// no historical state proofs. The bundle claims exactly what was captured; a verifier credits nothing for a named proof and names it. Captured
	// after the seal like the proofs it stands in for, so not part of BundleHash; it travels in BundleData, which ExportHash covers.
	UncapturedProofs []UncapturedProof `json:"uncapturedProofs,omitempty"`

	// PlanContentHash is the hash of the plan's content before it was bound to its policy evaluations (brief 28bu row 2): the plan hash
	// approvers sign is BindPlanHash(PlanContentHash, PolicyEvaluations), so a verifier recomputes it and holds every re-evaluated subject to
	// the hash the approvals signed. Zero for a plan governed under no evaluation (its plan hash is its content hash).
	PlanContentHash [32]byte `json:"planContentHash,omitempty"`

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
	PolicyDecisions  []DecisionProofRef `json:"policyDecisions,omitempty"`
	TrustAssumptions []TrustAssumption  `json:"trustAssumptions,omitempty"`
	ExternalProofs   []ExternalProofRef `json:"externalProofs,omitempty"`

	// PolicyEvaluations carries, for every policy the plan was decided under, the content-addressed policy and the subject it was decided
	// over, so a verifier re-runs the decision itself (policyeval, the node's own evaluator body) instead of reading PolicyDecisions. G0 is
	// credited only from these re-evaluations (native proof plan phase 6, brief 28bi). Covered by BundleHash when present.
	PolicyEvaluations []PolicyEvaluation `json:"policyEvaluations,omitempty"`

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

	// BundleHashRule names the rule BundleHash was computed under (brief 28cd, L3124). Finalize stamps BundleHashRuleSealedDigests on every
	// bundle it seals; absent (BundleHashRuleLegacy) is a bundle sealed before the rule existed, whose hash, already anchored on Accumulate,
	// must keep recomputing. The rule is itself hashed under the current rule, so a sealed bundle relabelled legacy no longer recomputes to
	// its anchored hash. A verifier reports a legacy bundle's outcome digest as NOT sealed (BundleHashCoversSealedDigests). Any other value
	// is refused.
	BundleHashRule int `json:"bundleHashRule,omitempty"`

	// OutcomeDigest is the deterministic digest of the canonical
	// OutcomeRecord referenced by OutcomeRecordID. It is set by upstream
	// callers (the executor hook, the mediator) before Finalize so the
	// portable evidence package can carry an outcome-bound proof
	// independent of bundle internals. Zero when no outcome is bound
	// (a subsystem-attributed bundle whose artifact is its outcome binds
	// the artifact's digest). Covered by BundleHash under the rule every
	// bundle is sealed under (BundleHashRuleSealedDigests; brief 28cd,
	// L3124), so it can never be the bundle's own hash, and a digest
	// swapped after sealing fails the recomputed BundleHash.
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

	// PluginVersions enumerates the production plugins whose
	// descriptors produced bundle content (every plugin call site
	// that records evidence calls EvidenceCollector.AddPluginVersion
	// at execution time). Surfaced into PortableEvidencePackage so
	// external auditors cross-check against their plugin inventory.
	// P1-005 closure (2026-05-02). Excluded from BundleHash because
	// the per-plugin hash already lives inside ImplementationHash; if
	// a plugin's behaviour changes its descriptor's hash flips, which
	// surfaces here as a different ImplementationHash entry.
	PluginVersions []PluginVersionEntry `json:"pluginVersions,omitempty"`
}

// ComputeBundleHash computes the SHA256 hash of the bundle's immutable
// content fields. The hash covers: intent/plan/outcome identifiers,
// evidence level, chain hash, state root, policy decisions, approval
// evidence, trust assumptions, external proofs, drift analysis, step
// outcomes (each with its per-category gas), policy evaluations, and
// (brief 28cd, L3124; under BundleHashRuleSealedDigests, the rule every
// bundle is sealed under) the rule number, the outcome digest, the anchor
// candidate digest, the plan content hash and the sealed block height,
// each under its own tag whether or not it is zero. It deliberately excludes mutable fields (anchor
// status, bundle state, timestamps) so that re-computing the hash
// after lifecycle transitions yields the same value.
//
// The function is stable and deterministic: it writes fields in a
// fixed order and relies on Go's stable JSON encoder for nested
// structures.
// AUDIT_RECHECK_2026-05-22_ROUND3-followup P0 closure: pre-closure
// the six per-component json.Marshal failures were silently discarded
// via `data, _`. On marshal failure the corresponding section was
// excluded from the hash and the digest collapsed to a value that
// did not bind to the actual content — a tampered evidence bundle
// with an unmarshalable component would produce a "valid" BundleHash
// indistinguishable from a clean bundle missing that component
// entirely. Propagate so Finalize and chain-verifiers fail closed.
func (b *EvidenceBundle) ComputeBundleHash() ([32]byte, error) {
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
		data, err := json.Marshal(b.PolicyDecisions)
		if err != nil {
			return [32]byte{}, fmt.Errorf("ComputeBundleHash: marshal PolicyDecisions for bundle intent=%s plan=%s: %w", b.IntentID, b.PlanID, err)
		}
		h.Write(data)
	}

	// Approval evidence.
	if len(b.ApprovalEvidence) > 0 {
		data, err := json.Marshal(b.ApprovalEvidence)
		if err != nil {
			return [32]byte{}, fmt.Errorf("ComputeBundleHash: marshal ApprovalEvidence for bundle intent=%s plan=%s: %w", b.IntentID, b.PlanID, err)
		}
		h.Write(data)
	}

	// Trust assumptions.
	if len(b.TrustAssumptions) > 0 {
		data, err := json.Marshal(b.TrustAssumptions)
		if err != nil {
			return [32]byte{}, fmt.Errorf("ComputeBundleHash: marshal TrustAssumptions for bundle intent=%s plan=%s: %w", b.IntentID, b.PlanID, err)
		}
		h.Write(data)
	}

	// External proofs.
	if len(b.ExternalProofs) > 0 {
		data, err := json.Marshal(b.ExternalProofs)
		if err != nil {
			return [32]byte{}, fmt.Errorf("ComputeBundleHash: marshal ExternalProofs for bundle intent=%s plan=%s: %w", b.IntentID, b.PlanID, err)
		}
		h.Write(data)
	}

	// Drift analysis.
	if b.DriftAnalysis != nil {
		data, err := json.Marshal(b.DriftAnalysis)
		if err != nil {
			return [32]byte{}, fmt.Errorf("ComputeBundleHash: marshal DriftAnalysis for bundle intent=%s plan=%s: %w", b.IntentID, b.PlanID, err)
		}
		h.Write(data)
	}

	// Step outcomes.
	if len(b.StepOutcomes) > 0 {
		data, err := json.Marshal(b.StepOutcomes)
		if err != nil {
			return [32]byte{}, fmt.Errorf("ComputeBundleHash: marshal StepOutcomes for bundle intent=%s plan=%s: %w", b.IntentID, b.PlanID, err)
		}
		h.Write(data)
	}

	// Policy evaluations (brief 28bi): tagged, so their bytes can never be read as another section's.
	if len(b.PolicyEvaluations) > 0 {
		data, err := json.Marshal(b.PolicyEvaluations)
		if err != nil {
			return [32]byte{}, fmt.Errorf("ComputeBundleHash: marshal PolicyEvaluations for bundle intent=%s plan=%s: %w", b.IntentID, b.PlanID, err)
		}
		h.Write([]byte("policyEvaluations"))
		h.Write(data)
	}

	// The sealed digests (brief 28cd, L3124). The outcome digest is what a portable package's OutcomeDigest is bound to and what the
	// anchor orchestrator anchors as the outcome; the anchor candidate digest (GAP-V4, spec §9.2.4) is what the bundle commits to anchor;
	// the plan content hash is what the approvals' plan hash is re-derived from (BindPlanHash); the sealed block height places the
	// bundle's trust snapshots in time. Each is written under its own tag and ALWAYS, zero included: a section written only when non-zero
	// would let a value be added to a bundle sealed without one and keep its hash. The rule's number is written first, so a sealed bundle
	// relabelled legacy recomputes to another hash. A legacy bundle keeps the rule it was anchored under: its anchor candidate, written only
	// when non-zero, and none of the others.
	switch b.BundleHashRule {
	case BundleHashRuleSealedDigests:
		var rule [8]byte
		binary.BigEndian.PutUint64(rule[:], uint64(b.BundleHashRule))
		h.Write([]byte("bundleHashRule"))
		h.Write(rule[:])
		h.Write([]byte("outcomeDigest"))
		h.Write(b.OutcomeDigest[:])
		h.Write([]byte("anchorCandidateDigest"))
		h.Write(b.AnchorCandidateDigest[:])
		h.Write([]byte("planContentHash"))
		h.Write(b.PlanContentHash[:])
		var height [8]byte
		binary.BigEndian.PutUint64(height[:], b.SealedBlockHeight)
		h.Write([]byte("sealedBlockHeight"))
		h.Write(height[:])
	case BundleHashRuleLegacy:
		var zero [32]byte
		if b.AnchorCandidateDigest != zero {
			h.Write(b.AnchorCandidateDigest[:])
		}
	default:
		return [32]byte{}, fmt.Errorf("ComputeBundleHash: bundle intent=%s plan=%s names bundle hash rule %d, which no verifier defines", b.IntentID, b.PlanID, b.BundleHashRule)
	}

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

// The bundle hash rules (EvidenceBundle.BundleHashRule; brief 28cd, L3124).
//
//   - BundleHashRuleLegacy: a bundle sealed before the rule was named. Its hash covers the anchor candidate digest when non-zero and
//     NOT the outcome digest, the plan content hash, the sealed block height or a zero anchor candidate; it is kept so that a bundle
//     already anchored on Accumulate still recomputes to its anchored hash, and a verifier reports what it leaves unsealed.
//   - BundleHashRuleSealedDigests: the rule Finalize seals every bundle under; it covers the rule number, the outcome digest, the anchor
//     candidate digest, the plan content hash and the sealed block height, each under its own tag, zero included.
const (
	BundleHashRuleLegacy        = 0
	BundleHashRuleSealedDigests = 2
	CurrentBundleHashRule       = BundleHashRuleSealedDigests
)

// BundleHashCoversSealedDigests reports whether b's BundleHash covers its outcome digest, anchor candidate digest, plan content hash and
// sealed block height; false for a legacy bundle, whose outcome digest a verifier must not report as sealed.
func (b *EvidenceBundle) BundleHashCoversSealedDigests() bool {
	return b.BundleHashRule == BundleHashRuleSealedDigests
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
	// a bundle sealed here for the first time is sealed under the current rule; one already sealed keeps its rule, so Finalize stays
	// idempotent and a legacy bundle keeps its anchored hash (brief 28cd, L3124)
	if b.BundleHash == ([32]byte{}) && b.BundleHashRule == BundleHashRuleLegacy {
		b.BundleHashRule = CurrentBundleHashRule
	}
	hash, hashErr := b.ComputeBundleHash()
	if hashErr != nil {
		return fmt.Errorf("Finalize: %w", hashErr)
	}
	b.BundleHash = hash
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
