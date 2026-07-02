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
)

// Proof is a linked-data proof over a credential or presentation.
type Proof struct {
	Type               string `json:"type"` // e.g. "Ed25519Signature2020"
	Created            string `json:"created,omitempty"`
	VerificationMethod string `json:"verificationMethod"` // issuer/holder key ref (DID#key)
	ProofPurpose       string `json:"proofPurpose,omitempty"`
	Challenge          string `json:"challenge,omitempty"` // VP: binds to a verifier nonce
	Domain             string `json:"domain,omitempty"`
	ProofValue         string `json:"proofValue"` // hex-encoded Ed25519 signature
}

// CredentialStatus references a revocation/status list entry (see
// evidence.CredentialStatusListRecord / CredentialRevocationRecord).
type CredentialStatus struct {
	ID              string `json:"id,omitempty"`
	Type            string `json:"type,omitempty"`
	StatusListID    string `json:"statusListId,omitempty"`
	StatusListIndex uint64 `json:"statusListIndex,omitempty"`
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

// SigningContent returns the deterministic bytes a holder signs for this
// presentation, bound to the verifier's challenge: SHA-256 of the proof-omitted
// presentation concatenated with the challenge. Passing the challenge explicitly
// keeps the binding unambiguous even if Proof.Challenge is absent.
func (vp VerifiablePresentation) SigningContent(challenge string) ([]byte, error) {
	unsigned := vp
	unsigned.Proof = nil
	b, err := json.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(b)
	h.Write([]byte(challenge))
	sum := h.Sum(nil)
	return sum[:], nil
}
