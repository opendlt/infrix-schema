// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package onboardingmetrics measures whether onboarding is actually improving
// (adoption-12): where users succeed, stall, and leave. It is privacy-first —
// CLI metrics are recorded LOCAL-ONLY by default and never transmitted; session
// ids are hashed; account URLs and other sensitive fields are redacted; private
// keys, proof contents, and full hashes are never stored. Error codes line up
// with the error-translation catalog (adoption-08) so failure points are
// nameable.
package onboardingmetrics

import (
	"fmt"
	"strings"
	"time"
)

// EventVersion is the current event schema version.
const EventVersion = "1"

// Sources of events.
const (
	SourceCLI    = "cli"
	SourceNexus  = "nexus"
	SourceCinema = "cinema"
	SourceSDK    = "sdk"
	SourceHosted = "hosted"
)

// Result values.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// Modes.
const (
	ModeLocal   = "local"
	ModeKermit  = "kermit"
	ModeMainnet = "mainnet"
)

// Canonical event names (the funnel). Kept as constants so producers and the
// summary agree on spelling.
const (
	// CLI lifecycle (recorded centrally for every command).
	EventCommandStarted   = "command.started"
	EventCommandSucceeded = "command.succeeded"
	EventCommandFailed    = "command.failed"
	EventDocsOpened       = "docs.opened"

	// Domain milestones (recorded by specific commands / surfaces).
	EventDemoStarted      = "demo.started"
	EventDemoCompleted    = "demo.completed"
	EventProofExported    = "proof.exported"
	EventProofVerified    = "proof.verified"
	EventCinemaOpened     = "cinema.opened"
	EventGuidedCompleted  = "guided.completed"
	EventShareReceipt     = "share.receipt"
	EventPersonaSelected  = "persona.selected"
	EventFirstPageLoaded  = "page.loaded"
	EventErrorStep        = "error.step"
)

// Event is one onboarding telemetry record. Its JSON form is the wire + on-disk
// schema (adoption-12). Optional fields are omitted when empty.
type Event struct {
	Version         string `json:"version"`
	Time            string `json:"time"`
	Source          string `json:"source"`
	SessionID       string `json:"sessionId"`
	Event           string `json:"event"`
	Command         string `json:"command,omitempty"`
	Persona         string `json:"persona,omitempty"`
	Mode            string `json:"mode,omitempty"`
	DurationMs      int64  `json:"durationMs,omitempty"`
	Result          string `json:"result,omitempty"`
	ErrorCode       string `json:"errorCode,omitempty"`
	ProofLevel      string `json:"proofLevel,omitempty"`
	GovernanceLevel string `json:"governanceLevel,omitempty"`
	Redacted        bool   `json:"redacted"`
}

var validSources = map[string]bool{
	SourceCLI: true, SourceNexus: true, SourceCinema: true, SourceSDK: true, SourceHosted: true,
}

var validResults = map[string]bool{"": true, ResultSuccess: true, ResultFailure: true}

var validModes = map[string]bool{"": true, ModeLocal: true, ModeKermit: true, ModeMainnet: true}

// Validate enforces the strict event schema. It is intentionally conservative:
// an unknown source/result/mode, a missing required field, or a non-RFC3339
// time is rejected, so a malformed or sensitive event never reaches the store.
func (e *Event) Validate() error {
	if e == nil {
		return fmt.Errorf("event is nil")
	}
	if e.Version != EventVersion {
		return fmt.Errorf("event version %q is not the supported %q", e.Version, EventVersion)
	}
	if !validSources[e.Source] {
		return fmt.Errorf("event source %q is not one of cli|nexus|cinema|sdk|hosted", e.Source)
	}
	if strings.TrimSpace(e.Event) == "" {
		return fmt.Errorf("event name is required")
	}
	if strings.TrimSpace(e.SessionID) == "" {
		return fmt.Errorf("sessionId is required")
	}
	if _, err := time.Parse(time.RFC3339, e.Time); err != nil {
		return fmt.Errorf("event time %q is not RFC3339: %w", e.Time, err)
	}
	if !validResults[e.Result] {
		return fmt.Errorf("event result %q is not one of success|failure", e.Result)
	}
	if !validModes[e.Mode] {
		return fmt.Errorf("event mode %q is not one of local|kermit|mainnet", e.Mode)
	}
	if e.DurationMs < 0 {
		return fmt.Errorf("durationMs must not be negative")
	}
	return nil
}
