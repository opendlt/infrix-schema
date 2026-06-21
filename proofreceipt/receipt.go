// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package proofreceipt is the stdlib-only compact proof-receipt schema:
// the wire types, the fail-closed Validate rules, and the text/HTML renderers
// for the ONE receipt that appears everywhere Infrix proves something — the
// CLI, the SDK, Nexus, Cinema, the examples, release evidence, and the hosted
// playground (adoption-06). It is the Tier-0 contract leaf carved out of
// pkg/proofreceipt (docs/extraction-plan); the per-surface converters that
// depend on verifykit/releasekit (from_verifykit.go / from_releasekit.go /
// from_metamask_acceptance.go) stay in the sibling pkg/proofreceipt, which
// re-exports this schema so existing importers are unaffected.
//
// A receipt answers the four questions a non-expert actually has —
// "was this verified? by whom? without trusting what? can I inspect the
// details?" — while letting an expert expand into the full cryptographic
// material via DetailsRef.
//
// The schema is fail-closed: Validate rejects any receipt that overclaims
// (L4 without L0, witness without L0, l0Verified without evidence, verified
// with no passing check, a missing nodeTrusted, conflicting artifact IDs).
package proofreceipt

import (
	"encoding/json"
	"fmt"
	"os"
)

// Version is the receipt schema version. It is a string so the schema can
// evolve without breaking parsers that key on it.
const Version = "1"

// Subject types — what a receipt is about.
const (
	SubjectIntent             = "intent"
	SubjectEvidence           = "evidence"
	SubjectRelease            = "release"
	SubjectMetaMaskAcceptance = "metamask_acceptance"
)

// Status values.
const (
	StatusVerified = "verified"
	StatusPartial  = "partial"
	StatusFailed   = "failed"
)

// Subject identifies what was proven.
type Subject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Assurance is the compact trust answer. NodeTrusted is a pointer so an
// omitted field (a structurally-invalid receipt) is distinguishable from an
// explicit false — Validate rejects a receipt that omits it.
type Assurance struct {
	ProofLevel            string `json:"proofLevel"`
	GovernanceLevel       string `json:"governanceLevel"`
	Label                 string `json:"label"`
	NodeTrusted           *bool  `json:"nodeTrusted"`
	L0Verified            bool   `json:"l0Verified"`
	ReplayVerified        bool   `json:"replayVerified"`
	WitnessQuorumVerified bool   `json:"witnessQuorumVerified"`
}

// Artifacts are the spine IDs a reader can pivot to. All are optional; the
// ones present must not conflict with the subject.
type Artifacts struct {
	IntentID   string `json:"intentId,omitempty"`
	PlanID     string `json:"planId,omitempty"`
	OutcomeID  string `json:"outcomeId,omitempty"`
	EvidenceID string `json:"evidenceId,omitempty"`
	AnchorTx   string `json:"anchorTx,omitempty"`
}

// Verification records who verified, how, and where.
type Verification struct {
	VerifiedAt string `json:"verifiedAt,omitempty"`
	Verifier   string `json:"verifier,omitempty"`
	Command    string `json:"command,omitempty"`
	Network    string `json:"network,omitempty"`
}

// Receipt is the canonical proof receipt.
type Receipt struct {
	Version      string       `json:"version"`
	Subject      Subject      `json:"subject"`
	Summary      string       `json:"summary"`
	Status       string       `json:"status"`
	Assurance    Assurance    `json:"assurance"`
	Artifacts    Artifacts    `json:"artifacts"`
	Verification Verification `json:"verification"`
	Warnings     []string     `json:"warnings"`
	DetailsRef   string       `json:"detailsRef,omitempty"`
}

// New returns a receipt skeleton with the current version and a non-nil
// warnings slice (so it always marshals "warnings": []).
func New() *Receipt {
	return &Receipt{Version: Version, Warnings: []string{}}
}

// BoolPtr is a convenience for setting Assurance.NodeTrusted. Exported so the
// per-surface converters in the sibling pkg/proofreceipt (from_*.go) can build
// an Assurance with an explicit nodeTrusted answer.
func BoolPtr(b bool) *bool { return &b }

// NodeTrusted reports the receipt's node-trust answer (false when omitted —
// callers should Validate to catch the omission).
func (r *Receipt) NodeTrusted() bool {
	return r.Assurance.NodeTrusted != nil && *r.Assurance.NodeTrusted
}

// ClaimsL4 reports whether the receipt asserts L0-confirmed L4 assurance.
func (r *Receipt) ClaimsL4() bool {
	return r.Assurance.L0Verified || IsLevelL4(r.Assurance.ProofLevel) || hasL4(r.Assurance.Label)
}

// MarshalJSONIndent returns the canonical pretty JSON.
func (r *Receipt) MarshalJSONIndent() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// WriteFile writes the receipt JSON to path (0600).
func (r *Receipt) WriteFile(path string) error {
	data, err := r.MarshalJSONIndent()
	if err != nil {
		return fmt.Errorf("proofreceipt: encode: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("proofreceipt: write %s: %w", path, err)
	}
	return nil
}

// Parse unmarshals a receipt from JSON without validating it.
func Parse(data []byte) (*Receipt, error) {
	var r Receipt
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("proofreceipt: parse: %w", err)
	}
	return &r, nil
}

// Load reads and parses a receipt file (no validation).
func Load(path string) (*Receipt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("proofreceipt: read %s: %w", path, err)
	}
	return Parse(data)
}
