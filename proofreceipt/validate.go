// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package proofreceipt

import (
	"fmt"
	"strings"
)

// Validate fails closed: it returns a non-nil error for any receipt that is
// structurally malformed or that OVERCLAIMS its assurance. The rules mirror
// the assurance ladder so a receipt can never assert more than it backs.
func Validate(r *Receipt) error {
	if r == nil {
		return fmt.Errorf("proofreceipt: nil receipt")
	}
	if r.Version != Version {
		return fmt.Errorf("proofreceipt: unsupported version %q (want %q)", r.Version, Version)
	}
	switch r.Subject.Type {
	case SubjectIntent, SubjectEvidence, SubjectRelease, SubjectMetaMaskAcceptance:
	default:
		return fmt.Errorf("proofreceipt: invalid subject.type %q", r.Subject.Type)
	}
	switch r.Status {
	case StatusVerified, StatusPartial, StatusFailed:
	default:
		return fmt.Errorf("proofreceipt: invalid status %q", r.Status)
	}

	a := r.Assurance
	// nodeTrusted must be explicit (a missing answer is itself a failure).
	if a.NodeTrusted == nil {
		return fmt.Errorf("proofreceipt: assurance.nodeTrusted is required (omitted)")
	}

	// A "verified" status needs at least one concrete check to have passed:
	// a real proof level, or an L0/replay/witness confirmation.
	if r.Status == StatusVerified {
		if !hasPositiveAssurance(a) {
			return fmt.Errorf("proofreceipt: status %q but no verification check passed (no proofLevel/L0/replay/witness)", StatusVerified)
		}
	}

	// L4 is only honest with an L0 confirmation.
	if isLevelL4(a.ProofLevel) && !a.L0Verified {
		return fmt.Errorf("proofreceipt: proofLevel L4 without l0Verified")
	}
	if hasL4(a.Label) && !a.L0Verified {
		return fmt.Errorf("proofreceipt: label %q claims L4 without l0Verified", a.Label)
	}

	// L0 confirmation must point at where + how it was confirmed (its evidence).
	if a.L0Verified {
		if strings.TrimSpace(r.Verification.Network) == "" {
			return fmt.Errorf("proofreceipt: l0Verified without a verification.network (L0 evidence)")
		}
		if strings.TrimSpace(r.Verification.Command) == "" {
			return fmt.Errorf("proofreceipt: l0Verified without a verification.command (live verification needs a command)")
		}
	}

	// Witness quorum sits above L0 on the ladder — it cannot be claimed alone.
	if a.WitnessQuorumVerified && !a.L0Verified {
		return fmt.Errorf("proofreceipt: witnessQuorumVerified without l0Verified")
	}

	// Artifact IDs must not contradict the subject.
	if err := checkArtifactConsistency(r); err != nil {
		return err
	}
	return nil
}

// hasPositiveAssurance reports whether the receipt carries at least one
// concrete, passed verification signal.
func hasPositiveAssurance(a Assurance) bool {
	return a.L0Verified || a.ReplayVerified || a.WitnessQuorumVerified || isProofLevel(a.ProofLevel)
}

func checkArtifactConsistency(r *Receipt) error {
	id := strings.TrimSpace(r.Subject.ID)
	switch r.Subject.Type {
	case SubjectIntent:
		if r.Artifacts.IntentID != "" && id != "" && r.Artifacts.IntentID != id {
			return fmt.Errorf("proofreceipt: subject.id %q conflicts with artifacts.intentId %q", id, r.Artifacts.IntentID)
		}
	case SubjectEvidence:
		if r.Artifacts.EvidenceID != "" && id != "" && r.Artifacts.EvidenceID != id {
			return fmt.Errorf("proofreceipt: subject.id %q conflicts with artifacts.evidenceId %q", id, r.Artifacts.EvidenceID)
		}
	}
	return nil
}

// --- level helpers (shared with receipt.go) ---

// isProofLevel reports whether s is a real proof level L1..L4 (not L0/empty).
func isProofLevel(s string) bool {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "L1", "L2", "L3", "L4":
		return true
	}
	return false
}

func isLevelL4(s string) bool { return strings.EqualFold(strings.TrimSpace(s), "L4") }

func hasL4(s string) bool { return strings.Contains(strings.ToUpper(s), "L4") }
