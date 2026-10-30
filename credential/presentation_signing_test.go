// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credential

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

// THE SHARED HOLDER-BINDING VECTOR. These literals are identical in infrix-schema (this file),
// infrix-verify (credverify/holder_vector_test.go) and infrix core (pkg/zkp/vc/holder_vector_test.go),
// the three independent implementations of the encoding. Changing one without the others breaks the
// build in the repository that drifted, which is the point.
const (
	vectorBody   = `{"@context":["https://www.w3.org/2018/credentials/v1"],"id":"urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5","type":["VerifiablePresentation"],"holder":"did:example:holder","verifiableCredential":[]}`
	vectorConfig = `{"challenge":"challenge-123","created":"2026-10-27T00:00:00Z","domain":"verifier.example","nonce":"nonce-456","proofPurpose":"authentication","type":"Ed25519Signature2020","verificationMethod":"did:example:holder#key-1"}`
	// vectorSigned is SHA-256(vectorConfig) || SHA-256(vectorBody).
	vectorSigned    = "0b167e707dcad14b0c59629b8f4e9c2ebcd8ac0f9c9da1f03b501b1bd37fdc0a0419f23d2a5cf30b8491a95b486035ddc81a6a47862fe862b6189f7c75547979"
	vectorPublicKey = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
	vectorSignature = "87626b45762a6173ceada98642be8884329f8f076116b3e12073cfab90c69b439140da97813574ff50e2d250a36279a50a9b1938c70aa60045ceacff88f5e60d"
	// The escaping vector: a configuration whose challenge needs every escape RFC 8785 defines.
	vectorEscapedConfig = "{\"challenge\":\"a\\\"b\\\\c\\nd é&<>\\u0001\",\"type\":\"T\"}"
	vectorEscapedHash   = "3c6f6a2c3d642c8dea62aed6000688dc92e40aabb5cea12d4042360cb06c8058"
)

func vectorPresentation() VerifiablePresentation {
	return VerifiablePresentation{
		Context: []string{"https://www.w3.org/2018/credentials/v1"}, ID: "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
		Type: []string{"VerifiablePresentation"}, Holder: "did:example:holder", VerifiableCredential: []VerifiableCredential{},
		Proof: &Proof{Type: "Ed25519Signature2020", Created: "2026-10-27T00:00:00Z", VerificationMethod: "did:example:holder#key-1",
			ProofPurpose: "authentication", Challenge: "challenge-123", Domain: "verifier.example", Nonce: "nonce-456"},
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestHolderSigningVector pins the body bytes, the canonical configuration, the 64 signed bytes and a
// signature over them.
func TestHolderSigningVector(t *testing.T) {
	vp := vectorPresentation()
	unsigned := vp
	unsigned.Proof = nil
	body, err := json.Marshal(unsigned)
	if err != nil || string(body) != vectorBody {
		t.Fatalf("the presentation body is not the vector body (a struct change moved the bytes): %s (%v)", body, err)
	}
	if got := string(vp.Proof.ProofConfigurationJSON()); got != vectorConfig {
		t.Fatalf("canonical configuration = %s, want %s", got, vectorConfig)
	}
	signed, err := vp.SigningContent("challenge-123")
	if err != nil || hex.EncodeToString(signed) != vectorSigned {
		t.Fatalf("signing content = %x (%v), want %s", signed, err, vectorSigned)
	}
	if !ed25519.Verify(mustHex(t, vectorPublicKey), signed, mustHex(t, vectorSignature)) {
		t.Fatal("the vector signature does not verify over the vector signing content")
	}
}

// TestCanonicalConfigurationEscapesAsRFC8785: the quotation mark, the reverse solidus and control
// characters are escaped; every other character, including & < > and non-ASCII, is raw UTF-8.
func TestCanonicalConfigurationEscapesAsRFC8785(t *testing.T) {
	cfg := Proof{Challenge: "a\"b\\c\nd é&<>\u0001", Type: "T"}
	got := cfg.ProofConfigurationJSON()
	if string(got) != vectorEscapedConfig {
		t.Fatalf("escaped configuration = %s, want %s", got, vectorEscapedConfig)
	}
	sum := sha256.Sum256(got)
	if hex.EncodeToString(sum[:]) != vectorEscapedHash {
		t.Fatalf("escaped configuration hash = %x, want %s", sum, vectorEscapedHash)
	}
}

// TestEveryConfigurationMemberIsBound plants one change per member of the proof configuration; the
// vector signature must stop verifying, so no member rides outside the signature. A binding that
// ignored a member would keep verifying, and the subtest for that member would fail.
func TestEveryConfigurationMemberIsBound(t *testing.T) {
	cases := map[string]func(*Proof){
		"type":               func(p *Proof) { p.Type = "Ed25519Signature2018" },
		"created":            func(p *Proof) { p.Created = "2026-10-28T00:00:00Z" },
		"verificationMethod": func(p *Proof) { p.VerificationMethod = "did:example:holder#key-2" },
		"proofPurpose":       func(p *Proof) { p.ProofPurpose = "assertionMethod" },
		"challenge":          func(p *Proof) { p.Challenge = "challenge-124" },
		"domain":             func(p *Proof) { p.Domain = "evil.example" },
		"nonce":              func(p *Proof) { p.Nonce = "nonce-457" },
	}
	for member, plant := range cases {
		t.Run(member, func(t *testing.T) {
			vp := vectorPresentation()
			plant(vp.Proof)
			signed, err := vp.SigningContent("")
			if err != nil {
				t.Fatal(err)
			}
			if ed25519.Verify(mustHex(t, vectorPublicKey), signed, mustHex(t, vectorSignature)) {
				t.Fatalf("PLANTED DEFECT NOT REFUSED: the vector signature still verifies after %s was changed", member)
			}
		})
	}
	t.Run("presentation body", func(t *testing.T) {
		vp := vectorPresentation()
		vp.Holder = "did:example:other"
		signed, _ := vp.SigningContent("")
		if ed25519.Verify(mustHex(t, vectorPublicKey), signed, mustHex(t, vectorSignature)) {
			t.Fatal("PLANTED DEFECT NOT REFUSED: the vector signature verifies a different presentation body")
		}
	})
}

// TestConcatenationBoundSignatureIsRefused is the refusal twin of the vector: a holder signature made
// the old way, over SHA-256(body || challenge), does not verify over the proof-configuration digest.
func TestConcatenationBoundSignatureIsRefused(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	h := sha256.New()
	h.Write([]byte(vectorBody))
	h.Write([]byte("challenge-123"))
	concatenated := ed25519.Sign(priv, h.Sum(nil))

	vp := vectorPresentation()
	signed, err := vp.SigningContent("challenge-123")
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(priv.Public().(ed25519.PublicKey), signed, concatenated) {
		t.Fatal("PLANTED DEFECT NOT REFUSED: a concatenation-bound holder signature verified")
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), signed, ed25519.Sign(priv, signed)) {
		t.Fatal("the proof-configuration-bound twin must verify")
	}
}

func TestSigningContentRefusesAChallengeThatIsNotTheProofs(t *testing.T) {
	vp := vectorPresentation()
	if _, err := vp.SigningContent("some-other-challenge"); !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("a verifier challenge that differs from the proof's must be refused, got %v", err)
	}
	vp.Proof = nil
	if _, err := vp.SigningContent("challenge-123"); err == nil {
		t.Fatal("a presentation with no proof configuration has nothing to bind and must be refused")
	}
	// A holder who signed WITHOUT a challenge cannot satisfy a verifier that demands one: the
	// demanded challenge enters the configuration the verifier hashes, and the signature was made
	// over a configuration without it.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	vp = vectorPresentation()
	vp.Proof.Challenge = ""
	unbound, err := vp.SigningContent("")
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(priv, unbound)
	demanded, err := vp.SigningContent("challenge-123")
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(priv.Public().(ed25519.PublicKey), demanded, signature) {
		t.Fatal("PLANTED DEFECT NOT REFUSED: a presentation signed without a challenge satisfied a verifier that demands one")
	}
}
