// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// THE SHARED did:infrix VECTOR SET (W.DID.CROSSSURFACE.PARITY), pinned in this module's CI.
//
// testdata/did-vectors-v1.json is the exact output of `infrix did vectors --out` in infrix core. The
// same file (the same SHA-256) is pinned in infrix-sdk-js and infrix-verify, and infrix core pins the
// digest of what it exports, so a change to the DID rules is a visible, simultaneous change in every
// repository.
//
// This module is a contract kernel, not a DID processor: it has no DID parser and its types carry
// identifiers as opaque strings. Parity for such a surface means one thing, and this test enforces
// it: the module NEVER ALTERS an identifier. Every vector input, valid or refused, must come back
// byte-identical through a credential and a presentation, and the signing content must not change
// under the round trip (a normalizing transport would make the signed bytes differ from what a
// parser-bearing surface signed).

const pinnedDIDVectorsSHA256 = "e25a465a066cbdbf746ca7abefed35d6d39e908120a2925b1844d761fc5e63cb"

type didVectorSet struct {
	Spec  string `json:"spec"`
	Parse []struct {
		Name      string `json:"name"`
		Input     string `json:"input"`
		Valid     bool   `json:"valid"`
		Canonical string `json:"canonical"`
	} `json:"parse"`
	Construct []struct {
		Name string `json:"name"`
	} `json:"construct"`
}

func loadDIDVectors(t *testing.T) (didVectorSet, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/did-vectors-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var set didVectorSet
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	return set, raw
}

func TestDIDVectorFileIsTheOneInfrixCoreExports(t *testing.T) {
	set, raw := loadDIDVectors(t)
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != pinnedDIDVectorsSHA256 {
		t.Fatalf("did vectors sha256 = %s, pinned %s: re-export with `infrix did vectors --out` and update every repository together", got, pinnedDIDVectorsSHA256)
	}
	if set.Spec != "did-infrix-v1" || len(set.Parse) < 26 || len(set.Construct) < 3 {
		t.Fatalf("vector set shape changed: spec %q, %d parse, %d construct", set.Spec, len(set.Parse), len(set.Construct))
	}
	// Planted defect: one extra byte must change the digest.
	edited := append(append([]byte(nil), raw...), ' ')
	if s := sha256.Sum256(edited); hex.EncodeToString(s[:]) == pinnedDIDVectorsSHA256 {
		t.Fatal("PLANTED DEFECT NOT DETECTED: an edited vector file kept the pinned digest")
	}
}

func TestEveryVectorIdentifierSurvivesTheSchemaByteForByte(t *testing.T) {
	set, _ := loadDIDVectors(t)
	for _, v := range set.Parse {
		t.Run(v.Name, func(t *testing.T) {
			vc := VerifiableCredential{
				Type: []string{"VerifiableCredential"}, Issuer: v.Input, IssuanceDate: "2026-10-27T00:00:00Z",
				CredentialSubject: map[string]any{"id": v.Input},
			}
			before, err := vc.SigningContent()
			if err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(vc)
			if err != nil {
				t.Fatal(err)
			}
			var back VerifiableCredential
			if err := json.Unmarshal(wire, &back); err != nil {
				t.Fatal(err)
			}
			if back.Issuer != v.Input || back.CredentialSubject["id"] != v.Input {
				t.Fatalf("the schema altered an identifier: issuer %q, subject %v, want %q", back.Issuer, back.CredentialSubject["id"], v.Input)
			}
			if after, _ := back.SigningContent(); hex.EncodeToString(after) != hex.EncodeToString(before) {
				t.Fatal("the signing content changed under a round trip of this identifier")
			}

			vp := VerifiablePresentation{Type: []string{"VerifiablePresentation"}, Holder: v.Input, VerifiableCredential: []VerifiableCredential{},
				Proof: &Proof{Type: "Ed25519Signature2020", VerificationMethod: v.Input + "#key-1", ProofPurpose: "authentication", Challenge: "c"}}
			wire, err = json.Marshal(vp)
			if err != nil {
				t.Fatal(err)
			}
			var vpBack VerifiablePresentation
			if err := json.Unmarshal(wire, &vpBack); err != nil || vpBack.Holder != v.Input || vpBack.Proof.VerificationMethod != v.Input+"#key-1" {
				t.Fatalf("the schema altered a holder identifier (%v): %q", err, vpBack.Holder)
			}
		})
	}
}

// TestPlantedDefectANormalizingTransportWouldBeCaught: a transport that lower-cased identifiers
// (the defect that splits surfaces) changes the mixed-case did:pkh vector, so the byte-for-byte
// assertion above is not vacuous.
func TestPlantedDefectANormalizingTransportWouldBeCaught(t *testing.T) {
	set, _ := loadDIDVectors(t)
	caught := false
	for _, v := range set.Parse {
		if v.Valid && strings.HasPrefix(v.Input, "did:pkh:") && strings.ToLower(v.Input) != v.Input {
			caught = true
		}
	}
	if !caught {
		t.Fatal("the vector set no longer carries a mixed-case identifier that a normalizing transport would corrupt; the planted defect is vacuous")
	}
}
