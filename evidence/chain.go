// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package evidence provides the cryptographic evidence chain that links
// intent → plan → policy decision → execution → outcome → state root
// into a single verifiable artifact.
package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"time"
)

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

// Verify checks that each link's PrevHash matches the previous link's
// ContentHash. This is a structural integrity check — it does not verify
// the content of the artifacts themselves.
func Verify(chain *EvidenceChain) bool {
	if len(chain.Links) == 0 {
		return true
	}
	// First link's PrevHash should be zero.
	if chain.Links[0].PrevHash != [32]byte{} {
		return false
	}
	for i := 1; i < len(chain.Links); i++ {
		if chain.Links[i].PrevHash != chain.Links[i-1].ContentHash {
			return false
		}
	}
	// Verify ChainHash.
	h := sha256.New()
	for _, link := range chain.Links {
		h.Write(link.ContentHash[:])
	}
	var expected [32]byte
	copy(expected[:], h.Sum(nil))
	return chain.ChainHash == expected
}
