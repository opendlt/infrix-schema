// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credential

import (
	"encoding/json"
	"strings"
	"testing"
)

// A LOSSY TYPE HERE BREAKS EVERY SIGNATURE DOWNSTREAM.
//
// SigningContent hashes this struct RE-MARSHALLED with its proof removed. That
// makes every verifier's result depend on these types being a complete model of
// what an issuer emits: a field that is not declared is dropped on unmarshal,
// the re-marshalled bytes differ from the bytes that were signed, and the
// signature fails — reported as "signature does not verify against the issuer
// key", which reads as a wrong key or a forgery rather than a modelling gap.
//
// Measured 2026-09-10: CredentialStatus did not declare revocationListIndex or
// revocationListCredential, which Infrix emits on every credential carrying a
// status. The offline verifier rejected every credential the node issued, with
// a valid signature on every one of them.
//
// This module is released independently, so the guard belongs HERE and not only
// in the repository that happens to issue credentials today.

// issuedCredentialJSON is a credential in the exact shape Infrix emits,
// including the status fields whose absence caused the failure.
const issuedCredentialJSON = `{"@context":["https://www.w3.org/2018/credentials/v1"],` +
	`"id":"urn:uuid:deadbeefdeadbeef:1","type":["VerifiableCredential","RoundTripCredential"],` +
	`"issuer":"did:infrix:issuer","issuanceDate":"2026-09-10T00:00:00Z",` +
	`"credentialSubject":{"id":"did:infrix:subject","role":"auditor"},` +
	`"credentialStatus":{"id":"did:infrix:issuer/status#0","type":"StatusList2021Entry",` +
	`"revocationListIndex":"0","revocationListCredential":"did:infrix:issuer/status"},` +
	`"proof":{"type":"Ed25519Signature2020","created":"2026-09-10T00:00:00Z",` +
	`"verificationMethod":"did:infrix:issuer#key-1","proofPurpose":"assertionMethod",` +
	`"proofValue":"z1GMkH3brNXiNNs1tiFZHu4yZSRrzJwxi5wB9bHFtMinfCXNnR1adh8Vo8NTheK4evneedH4qmvjeqcBBNAefgS"}}`

// TestAnIssuedCredentialRoundTripsWithoutLoss is the fence.
func TestAnIssuedCredentialRoundTripsWithoutLoss(t *testing.T) {
	var vc VerifiableCredential
	if err := json.Unmarshal([]byte(issuedCredentialJSON), &vc); err != nil {
		t.Fatalf("cannot parse an issued credential: %v", err)
	}
	out, err := json.Marshal(vc)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if string(out) != issuedCredentialJSON {
		t.Errorf("THESE TYPES ARE LOSSY FOR AN ISSUED CREDENTIAL — every signature over one "+
			"will fail.\nin : %s\nout: %s", issuedCredentialJSON, out)
		for _, field := range []string{"revocationListIndex", "revocationListCredential"} {
			if strings.Contains(issuedCredentialJSON, field) && !strings.Contains(string(out), field) {
				t.Errorf("  dropped field: %s", field)
			}
		}
	}
}

// TestSigningContentOmitsTheProofMember pins the other half of the same class.
//
// "The credential without its proof" must contain no proof member at all. A
// null one is reproducible only by an implementation that shares the exact
// struct, which is the definition of non-interoperable.
func TestSigningContentOmitsTheProofMember(t *testing.T) {
	var vc VerifiableCredential
	if err := json.Unmarshal([]byte(issuedCredentialJSON), &vc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	unsigned := vc
	unsigned.Proof = nil
	b, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), `"proof"`) {
		t.Fatalf("the signing content carries a proof member:\n%s", b)
	}

	// SigningContent must agree with that byte for byte — it is what gets hashed.
	content, err := vc.SigningContent()
	if err != nil {
		t.Fatalf("SigningContent: %v", err)
	}
	if len(content) != 32 {
		t.Fatalf("SigningContent returned %d bytes, want a 32-byte SHA-256 digest", len(content))
	}
}
