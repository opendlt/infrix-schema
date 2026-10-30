// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package credential is the wire-stable data model for Infrix Verifiable
// Credentials (VC) and Verifiable Presentations (VP), plus the deterministic
// signing content an issuer/holder signs and a verifier recomputes. It is
// stdlib-only (the infrix-schema contract fence): signing and verification live
// in the consumer (an issuer, or infrix-verify/credverify), never here.
//
// Signatures use Ed25519 over the SHA-256 of the canonical, proof-omitted JSON
// (an SD-JWT-style linked-data proof) — no pairing crypto, so a verifier needs
// only crypto/ed25519 (DX P1-4).
package credential

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// Proof is a linked-data proof over a credential or presentation.
type Proof struct {
	Type               string `json:"type"` // e.g. "Ed25519Signature2020"
	Created            string `json:"created,omitempty"`
	VerificationMethod string `json:"verificationMethod"` // issuer/holder key ref (DID#key)
	ProofPurpose       string `json:"proofPurpose,omitempty"`
	Challenge          string `json:"challenge,omitempty"` // VP: binds to a verifier nonce
	Domain             string `json:"domain,omitempty"`
	Nonce              string `json:"nonce,omitempty"` // VP: binds to one verifier session
	ProofValue         string `json:"proofValue"`      // hex-encoded Ed25519 signature
}

// CredentialStatus is a credential's StatusList2021Entry.
//
// The standard members (https://www.w3.org/community/reports/credentials/CG-FINAL-vc-status-list-2021-20230102/)
// are statusPurpose, statusListIndex and statusListCredential, and statusListIndex is a STRING
// ("94567"), not a number. New credentials carry only those. The two RevocationList2020 members
// below them are what the issuer wrote under the same entry type before Wave D1d; a credential
// issued then must still parse and verify, so the model keeps them, and Resolve names that form
// with an explicit legacy label instead of treating the two spellings as one.
//
// Every member must be modelled: a member this struct does not declare is DROPPED on
// unmarshal, so the re-marshalled credential SigningContent hashes is not the document the
// issuer signed and every signature fails (measured 2026-09-10; see
// TestSigningContentSurvivesAnInfrixCredentialRoundTrip). Declaration order is marshalling
// order: id, type, the legacy pair, then the standard members.
type CredentialStatus struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`

	// RevocationListIndex and RevocationListCredential are the RevocationList2020 member names
	// the issuer wrote before Wave D1d. Read-only legacy: Resolve labels them, no producer writes them.
	RevocationListIndex      string `json:"revocationListIndex,omitempty"`
	RevocationListCredential string `json:"revocationListCredential,omitempty"`

	// StatusPurpose is "revocation" or "suspension".
	StatusPurpose string `json:"statusPurpose,omitempty"`
	// StatusListIndex is the entry's position in the list, an unsigned decimal string.
	StatusListIndex string `json:"statusListIndex,omitempty"`
	// StatusListCredential is the URL of the StatusList2021Credential.
	StatusListCredential string `json:"statusListCredential,omitempty"`
}

// StatusForm names which member spelling a status entry uses.
type StatusForm string

const (
	// StatusFormStandard is the StatusList2021 spelling: statusPurpose, statusListIndex, statusListCredential.
	StatusFormStandard StatusForm = "StatusList2021"
	// StatusFormLegacyRevocationList2020 is the earlier spelling, accepted ONLY under this label.
	StatusFormLegacyRevocationList2020 StatusForm = "legacy:RevocationList2020"
)

// ErrStatusEntry is returned for an entry that is neither wholly standard nor wholly legacy.
var ErrStatusEntry = errors.New("credential: malformed credentialStatus entry")

// Resolve returns the entry's form, the status list credential URL and the index, or
// ErrStatusEntry: a standard entry needs a defined statusPurpose, a decimal statusListIndex
// and a statusListCredential; a legacy entry needs both RevocationList2020 members; an entry
// that carries members of both spellings is refused because it would read as two different positions.
func (s CredentialStatus) Resolve() (form StatusForm, list, index string, err error) {
	standard := s.StatusPurpose != "" || s.StatusListIndex != "" || s.StatusListCredential != ""
	legacy := s.RevocationListIndex != "" || s.RevocationListCredential != ""
	switch {
	case standard && legacy:
		return "", "", "", fmt.Errorf("%w: it carries both the StatusList2021 and the RevocationList2020 member names", ErrStatusEntry)
	case standard:
		if s.StatusPurpose != "revocation" && s.StatusPurpose != "suspension" {
			return "", "", "", fmt.Errorf("%w: statusPurpose %q is neither revocation nor suspension", ErrStatusEntry, s.StatusPurpose)
		}
		if n, perr := strconv.ParseUint(s.StatusListIndex, 10, 64); perr != nil || strconv.FormatUint(n, 10) != s.StatusListIndex {
			return "", "", "", fmt.Errorf("%w: statusListIndex %q is not an unsigned decimal string", ErrStatusEntry, s.StatusListIndex)
		}
		if s.StatusListCredential == "" {
			return "", "", "", fmt.Errorf("%w: statusListCredential is empty", ErrStatusEntry)
		}
		return StatusFormStandard, s.StatusListCredential, s.StatusListIndex, nil
	case legacy:
		if s.RevocationListIndex == "" || s.RevocationListCredential == "" {
			return "", "", "", fmt.Errorf("%w: a RevocationList2020 entry needs both revocationListIndex and revocationListCredential", ErrStatusEntry)
		}
		return StatusFormLegacyRevocationList2020, s.RevocationListCredential, s.RevocationListIndex, nil
	}
	return "", "", "", fmt.Errorf("%w: no status list members", ErrStatusEntry)
}

// VerifiableCredential is a signed set of claims an issuer makes about a subject.
type VerifiableCredential struct {
	Context           []string          `json:"@context,omitempty"`
	ID                string            `json:"id,omitempty"`
	Type              []string          `json:"type"`
	Issuer            string            `json:"issuer"` // issuer DID
	IssuanceDate      string            `json:"issuanceDate,omitempty"`
	ExpirationDate    string            `json:"expirationDate,omitempty"` // RFC3339
	CredentialSubject map[string]any    `json:"credentialSubject"`
	CredentialStatus  *CredentialStatus `json:"credentialStatus,omitempty"`
	Proof             *Proof            `json:"proof,omitempty"`
}

// VerifiablePresentation is a holder-assembled package of one or more VCs,
// bound to a verifier challenge so it cannot be replayed.
type VerifiablePresentation struct {
	Context              []string               `json:"@context,omitempty"`
	ID                   string                 `json:"id,omitempty"`
	Type                 []string               `json:"type"`
	Holder               string                 `json:"holder"` // holder DID
	VerifiableCredential []VerifiableCredential `json:"verifiableCredential"`
	Proof                *Proof                 `json:"proof,omitempty"`
}

// SigningContent returns the deterministic bytes an issuer signs for this
// credential: SHA-256 of the credential canonically serialized with its Proof
// omitted. A verifier recomputes this and checks Proof.ProofValue against it.
func (vc VerifiableCredential) SigningContent() ([]byte, error) {
	unsigned := vc
	unsigned.Proof = nil
	b, err := json.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}
