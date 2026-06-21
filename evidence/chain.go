// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package evidence provides the stdlib-only contract/verification
// kernel for governed-execution evidence: the cryptographic evidence chain
// that links intent → plan → policy decision → execution → outcome → state
// root, the evidence bundle and portable-package wire formats, and their
// offline verifiers. It depends on no other Infrix package so it can be
// extracted as the leaf contract module (see docs/extraction-plan).
package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// StateRootProvider returns the current Merkle state root. Implemented by
// pkg/state.StateManager. The evidence package declares this interface
// locally so it can capture a real state root at Build() time without
// importing pkg/state (which would create an import cycle).
type StateRootProvider interface {
	Root() [32]byte
}

// Evidence link types for capability operations (Phase G09-12).
const (
	EvidenceLinkCapabilityGrant    = "capability_grant"
	EvidenceLinkCapabilityRevoke   = "capability_revoke"
	EvidenceLinkCapabilityExercise = "capability_exercise"
	EvidenceLinkCapabilityDenied   = "capability_denied"
	EvidenceLinkGrantState         = "grant_state_snapshot"
	EvidenceLinkDelegationChain    = "delegation_chain"
)

// Evidence link types for role operations (Phase G10-7).
const (
	EvidenceLinkSoDViolation = "sod_violation"
)

// Evidence link types for credential status lifecycle.
const (
	EvidenceLinkCredentialRevocation = "credential_revocation"
	EvidenceLinkCredentialStatusList = "credential_status_list"
	EvidenceLinkRawTxWrappedAsIntent = "raw_tx_wrapped_as_intent"
)

// Evidence link types for governed role lifecycle (Phase G10-13).
//
// These types capture role-related artifacts produced during governed
// execution so auditors can reconstruct who held which roles, what
// separation-of-duties checks were performed, and why emergency grants
// were issued — all without replaying the full block history.
const (
	// EvidenceLinkRoleState snapshots every active role held by an identity
	// at execution time.
	EvidenceLinkRoleState = "role_state"
	// EvidenceLinkRoleAssignment records a RoleBinding that was created as
	// part of a governed intent.
	EvidenceLinkRoleAssignment = "role_assignment"
	// EvidenceLinkRoleRevocation records a RoleBinding that was revoked as
	// part of a governed intent.
	EvidenceLinkRoleRevocation = "role_revocation"
	// EvidenceLinkRoleSoDCheck captures the result of a separation-of-duties
	// evaluation performed during approval collection.
	EvidenceLinkRoleSoDCheck = "role_sod_check"
	// EvidenceLinkRoleEmergencyGrant records an emergency role grant along
	// with its justification for after-the-fact review.
	EvidenceLinkRoleEmergencyGrant = "role_emergency_grant"
)

// RoleSnapshot is a minimal projection of a RoleBinding captured inside a
// role_state evidence link. It intentionally avoids importing the role or
// objects packages to keep the evidence package dependency-free.
type RoleSnapshot struct {
	BindingID string `json:"bindingID"`
	RoleName  string `json:"roleName"`
	Scope     string `json:"scope"`
	State     string `json:"state"`
}

// RoleSoDApprover identifies a single approver inside a role_sod_check
// evidence payload.
type RoleSoDApprover struct {
	Identity string `json:"identity"`
	Role     string `json:"role"`
}

// CapabilityExerciseRecord captures a single capability accessor invocation
// against an ExecutionContextView. Persisted as a capability_exercise (or
// capability_denied when Allowed=false) link in the evidence chain. The
// PluginID identifies the descriptor whose manifest contained (or did not
// contain) the required capability; auditors can correlate this with the
// step plugin selection record. Spec §7.4 — "capability exercise is
// evidence-addressable" (GAP-V15 closure 2026-04-30).
type CapabilityExerciseRecord struct {
	PluginID   string    `json:"pluginId,omitempty"`
	StepID     string    `json:"stepId,omitempty"`
	Capability string    `json:"capability"`
	Method     string    `json:"method"`
	Allowed    bool      `json:"allowed"`
	At         time.Time `json:"at,omitzero"`
}

// GrantStateSnapshot captures the resolved CapabilityGrant state at the
// moment the grant satisfied a host capability check. Stored as a
// grant_state_snapshot link so auditors can reconstruct which grant
// authorized which exercise without replaying the L0 chain. GAP-V15
// closure 2026-04-30.
type GrantStateSnapshot struct {
	GrantID         string `json:"grantId"`
	ContractAddr    string `json:"contractAddr"`
	Capability      string `json:"capability"`
	GrantState      string `json:"grantState"`
	BlockHeight     uint64 `json:"blockHeight"`
	ExpiresAt       uint64 `json:"expiresAt,omitempty"`
	DelegationDepth uint64 `json:"delegationDepth,omitempty"`
	ConditionsMet   bool   `json:"conditionsMet"`
}

// DelegationChainRecord captures the full delegation chain for an exercised
// CapabilityGrant. Stored as a delegation_chain link when a delegated grant
// is consumed. GAP-V15 closure 2026-04-30.
type DelegationChainRecord struct {
	GrantID   string   `json:"grantId"`
	ChainIDs  []string `json:"chainIds"`
	MaxDepth  uint64   `json:"maxDepth,omitempty"`
	RootGrant string   `json:"rootGrant,omitempty"`
}

type CredentialRevocationRecord struct {
	CredentialID   string `json:"credentialId"`
	StatusListID   string `json:"statusListId"`
	Index          uint64 `json:"index"`
	Actor          string `json:"actor"`
	Reason         string `json:"reason"`
	IntentID       string `json:"intentId"`
	PlanID         string `json:"planId"`
	RevokedAtBlock uint64 `json:"revokedAtBlock"`
	SnapshotDigest string `json:"snapshotDigest,omitempty"`
	AnchorID       string `json:"anchorId,omitempty"`
}

type CredentialStatusListRecord struct {
	StatusListID string `json:"statusListId"`
	Digest       string `json:"digest"`
	BlockHeight  uint64 `json:"blockHeight,omitempty"`
	IntentID     string `json:"intentId,omitempty"`
	PlanID       string `json:"planId,omitempty"`
}

// EvidenceChain is a hash-linked sequence of artifacts produced during
// intent execution. Each link's PrevHash references the previous link's
// ContentHash, forming a tamper-evident chain. The ChainHash is the
// SHA256 of all link hashes concatenated.
type EvidenceChain struct {
	IntentID  string         `json:"intentId"`
	Links     []EvidenceLink `json:"links"`
	StateRoot [32]byte       `json:"stateRoot"`
	ChainHash [32]byte       `json:"chainHash"`
	CreatedAt time.Time      `json:"createdAt"`

	// G-14 Phase G14-12: anchor reference. Set by the orchestrator
	// once the chain's ChainHash has been anchored to L0 via an
	// AnchoredRecord. AnchorStatus mirrors the AnchoredRecord state
	// machine ("pending" | "confirmed" | "verified" | "failed") so
	// auditors can tell whether the anchor has been independently
	// verified against Accumulate. AnchoredAt is the wall-clock time
	// at which the status was last updated; it is zero when the chain
	// has not yet been anchored.
	AnchorID     string    `json:"anchorId,omitempty"`
	AnchorStatus string    `json:"anchorStatus,omitempty"`
	AnchoredAt   time.Time `json:"anchoredAt,omitzero"`
}

// EvidenceLink is a single artifact in the evidence chain.
type EvidenceLink struct {
	Sequence    uint64    `json:"sequence"`
	Type        string    `json:"type"` // "intent", "plan", "policy_decision", "execution", "outcome"
	ContentHash [32]byte  `json:"contentHash"`
	PrevHash    [32]byte  `json:"prevHash"`
	Timestamp   time.Time `json:"timestamp"`
	ArtifactRef string    `json:"artifactRef,omitempty"`
}

// Builder accumulates evidence links during intent execution.
type Builder struct {
	intentID string
	links    []EvidenceLink
	seq      uint64
}

// NewBuilder creates a new evidence chain builder for the given intent.
func NewBuilder(intentID string) *Builder {
	return &Builder{intentID: intentID}
}

// AddLink appends a new evidence link. The content is hashed and linked
// to the previous entry.
func (b *Builder) AddLink(linkType string, content []byte, artifactRef string) {
	contentHash := sha256.Sum256(content)
	var prevHash [32]byte
	if len(b.links) > 0 {
		prevHash = b.links[len(b.links)-1].ContentHash
	}
	b.seq++
	b.links = append(b.links, EvidenceLink{
		Sequence:    b.seq,
		Type:        linkType,
		ContentHash: contentHash,
		PrevHash:    prevHash,
		Timestamp:   time.Now(),
		ArtifactRef: artifactRef,
	})
}

// AddJSON marshals the value to JSON and adds it as a link.
func (b *Builder) AddJSON(linkType string, value any, artifactRef string) {
	data, err := json.Marshal(value)
	if err != nil {
		data = []byte("{}")
	}
	b.AddLink(linkType, data, artifactRef)
}

// AddGhostEvidence adds a ghost simulation evidence link to the chain.
// The ghost evidence is serialized as JSON and linked with type "ghost_simulation".
func (b *Builder) AddGhostEvidence(evidence any) {
	b.AddJSON("ghost_simulation", evidence, "ghost-sim-"+b.intentID)
}

// AddComplianceViolation adds a compliance violation evidence link.
// The violation is serialized as JSON and linked with type "compliance_violation".
func (b *Builder) AddComplianceViolation(violation any, invariantID string) {
	b.AddJSON("compliance_violation", violation, "violation-"+invariantID)
}

// AddForensicAnalysis adds a forensic analysis evidence link to the chain.
// The forensic report is serialized as JSON and linked with type "forensic_analysis".
func (b *Builder) AddForensicAnalysis(report any, forensicID string) {
	b.AddJSON("forensic_analysis", report, "forensic-"+forensicID)
}

// AddSoDViolation records a separation-of-duties violation as an evidence
// link (G-10 Phase 7). It captures the identity attempting the action, the
// role they tried to take on, the conflicting role they already hold, and
// the binding ID of that conflicting role. The artifact reference points to
// the blocking binding so auditors can navigate directly to it.
func (b *Builder) AddSoDViolation(identity, attemptedRole, conflictingRole, conflictingBindingID string) {
	payload := map[string]any{
		"identity":             identity,
		"attemptedRole":        attemptedRole,
		"conflictingRole":      conflictingRole,
		"conflictingBindingID": conflictingBindingID,
	}
	b.AddJSON(EvidenceLinkSoDViolation, payload, "role_binding://"+conflictingBindingID)
}

// AddRoleState records a snapshot of all active roles held by the given
// identity at execution time (Phase G10-13). The blockHeight is captured
// alongside the snapshot so auditors can correlate with the L0 chain.
func (b *Builder) AddRoleState(identity string, activeRoles []RoleSnapshot, blockHeight uint64) {
	payload := map[string]any{
		"identity":    identity,
		"activeRoles": activeRoles,
		"blockHeight": blockHeight,
	}
	b.AddJSON(EvidenceLinkRoleState, payload, "role_state://"+identity)
}

// AddRoleAssignment records a RoleBinding that was created through a
// governed intent (Phase G10-13). The fields map should mirror the fields
// written to the RoleBinding object so the evidence is self-contained.
func (b *Builder) AddRoleAssignment(bindingID string, fields map[string]any) {
	payload := map[string]any{
		"bindingID": bindingID,
		"fields":    fields,
	}
	b.AddJSON(EvidenceLinkRoleAssignment, payload, "role_binding://"+bindingID)
}

// AddRoleRevocation records a RoleBinding revocation performed through a
// governed intent (Phase G10-13).
func (b *Builder) AddRoleRevocation(bindingID, revoker, reason string) {
	payload := map[string]any{
		"bindingID": bindingID,
		"revoker":   revoker,
		"reason":    reason,
	}
	b.AddJSON(EvidenceLinkRoleRevocation, payload, "role_binding://"+bindingID)
}

// AddRoleSoDCheck records the result of a separation-of-duties evaluation
// performed as part of an approval stage with EnforceSeparationOfDuties
// (Phase G10-13). The sodSatisfied flag captures whether the check passed.
func (b *Builder) AddRoleSoDCheck(identity string, requiredRoles []string, approvers []RoleSoDApprover, sodSatisfied bool) {
	payload := map[string]any{
		"identity":      identity,
		"requiredRoles": requiredRoles,
		"approvers":     approvers,
		"sodSatisfied":  sodSatisfied,
	}
	b.AddJSON(EvidenceLinkRoleSoDCheck, payload, "role_sod_check://"+identity)
}

// AddRoleEmergencyGrant records an emergency role grant along with its
// justification (Phase G10-13). Emergency grants bypass some normal
// approvals and therefore require after-the-fact evidence for audit.
func (b *Builder) AddRoleEmergencyGrant(bindingID string, fields map[string]any, justification string) {
	payload := map[string]any{
		"bindingID":     bindingID,
		"fields":        fields,
		"justification": justification,
	}
	b.AddJSON(EvidenceLinkRoleEmergencyGrant, payload, "role_binding://"+bindingID)
}

// AddCapabilityExercise records a single allowed capability accessor
// invocation against an ExecutionContextView. Spec §7.4 — capability
// exercise is evidence-addressable (GAP-V15 closure 2026-04-30). The
// artifact reference uses the canonical capability:// scheme plus the
// (pluginID, stepID, capability) tuple so auditors can scope the search
// to a single step / plugin / capability.
func (b *Builder) AddCapabilityExercise(rec CapabilityExerciseRecord) {
	ref := "capability://" + rec.PluginID + "/" + rec.StepID + "/" + rec.Capability
	b.AddJSON(EvidenceLinkCapabilityExercise, rec, ref)
}

// AddCapabilityDenied records a denied capability accessor invocation
// (Allowed=false on the ExecutionContextView gate). The denial side of
// the §7.4 evidence-addressable contract: an undeclared capability
// request must produce a durable artifact even though the call returned
// ErrCapabilityDenied. GAP-V15 closure 2026-04-30.
func (b *Builder) AddCapabilityDenied(rec CapabilityExerciseRecord) {
	ref := "capability://" + rec.PluginID + "/" + rec.StepID + "/" + rec.Capability + "/denied"
	b.AddJSON(EvidenceLinkCapabilityDenied, rec, ref)
}

// AddGrantStateSnapshot records the resolved CapabilityGrant state at
// the moment a host CheckCall consumed it. Captures the GrantID,
// contract address, capability, grant state, expiration, and delegation
// depth so auditors can trace which grant authorized which exercise
// without replaying L0. GAP-V15 closure 2026-04-30.
func (b *Builder) AddGrantStateSnapshot(rec GrantStateSnapshot) {
	ref := "grant://" + rec.GrantID
	b.AddJSON(EvidenceLinkGrantState, rec, ref)
}

// AddDelegationChain records the full ancestor chain of a delegated
// CapabilityGrant at the moment it satisfied a CheckCall. Emitted only
// when the resolved grant has a non-empty DelegationChain so the
// non-delegated common case stays out of the chain. GAP-V15 closure
// 2026-04-30.
func (b *Builder) AddDelegationChain(rec DelegationChainRecord) {
	ref := "grant://" + rec.GrantID + "/delegation_chain"
	b.AddJSON(EvidenceLinkDelegationChain, rec, ref)
}

func (b *Builder) AddCredentialRevocation(rec CredentialRevocationRecord) {
	b.AddJSON(EvidenceLinkCredentialRevocation, rec, "credential://"+rec.CredentialID+"/revocation")
}

func (b *Builder) AddCredentialStatusList(rec CredentialStatusListRecord) {
	b.AddJSON(EvidenceLinkCredentialStatusList, rec, "credential_status_list://"+rec.StatusListID)
}

// Links returns the accumulated evidence links. Primarily used by tests and
// callers that need to inspect the chain prior to Build().
func (b *Builder) Links() []EvidenceLink {
	return b.links
}

// Build finalizes the chain, computing the ChainHash from all link hashes.
func (b *Builder) Build(stateRoot [32]byte) *EvidenceChain {
	chain := &EvidenceChain{
		IntentID:  b.intentID,
		Links:     b.links,
		StateRoot: stateRoot,
		CreatedAt: time.Now(),
	}
	// ChainHash = SHA256(link1.ContentHash || link2.ContentHash || ...)
	h := sha256.New()
	for _, link := range b.links {
		h.Write(link.ContentHash[:])
	}
	copy(chain.ChainHash[:], h.Sum(nil))
	return chain
}

// VerifyChainIntegrity checks the structural integrity of an evidence chain.
// It returns nil if the chain is valid, or a descriptive error identifying
// the first structural failure (nil chain, broken PrevHash link, or
// mismatched ChainHash). It does NOT verify the content of the artifacts
// themselves — only the cryptographic linking between links and the
// top-level chain hash.
func VerifyChainIntegrity(chain *EvidenceChain) error {
	if chain == nil {
		return errors.New("evidence: chain is nil")
	}
	if len(chain.Links) == 0 {
		return nil // empty chain is trivially valid
	}

	// First link's PrevHash must be zero (genesis).
	if chain.Links[0].PrevHash != [32]byte{} {
		return fmt.Errorf("evidence: link[0] PrevHash is non-zero (expected genesis)")
	}

	// Each subsequent link's PrevHash must equal the previous link's ContentHash.
	for i := 1; i < len(chain.Links); i++ {
		if chain.Links[i].PrevHash != chain.Links[i-1].ContentHash {
			return fmt.Errorf("evidence: link[%d] PrevHash mismatch: expected %x, got %x",
				i, chain.Links[i-1].ContentHash, chain.Links[i].PrevHash)
		}
	}

	// Verify ChainHash = SHA256(link1.ContentHash || link2.ContentHash || ...).
	h := sha256.New()
	for _, link := range chain.Links {
		h.Write(link.ContentHash[:])
	}
	var expected [32]byte
	copy(expected[:], h.Sum(nil))
	if chain.ChainHash != expected {
		return fmt.Errorf("evidence: ChainHash mismatch: expected %x, got %x",
			expected, chain.ChainHash)
	}

	return nil
}

// MARKER-AUDIT 2026-06-10 closure: the Deprecated boolean Verify
// wrapper was deleted — its only callers were tests, all migrated to
// VerifyChainIntegrity, which returns a descriptive error identifying
// the specific integrity failure.
