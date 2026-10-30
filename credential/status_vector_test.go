// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credential

import (
	"encoding/json"
	"errors"
	"testing"
)

// THE SHARED StatusList2021Entry VECTOR.
//
// The same two literals sit in infrix-core (pkg/zkp/vc/status_vector_test.go) and infrix-verify
// (credverify/status_vector_test.go). Each repository parses and re-marshals them with its own types,
// so a member renamed in one place fails the other two. The entry is the one the StatusList2021
// specification shows: statusPurpose, statusListIndex (a STRING) and statusListCredential.
const (
	statusEntryVector       = `{"id":"https://issuer.example/status/3#94567","type":"StatusList2021Entry","statusPurpose":"revocation","statusListIndex":"94567","statusListCredential":"https://issuer.example/status/3"}`
	legacyStatusEntryVector = `{"id":"https://issuer.example/status/3#94567","type":"StatusList2021Entry","revocationListIndex":"94567","revocationListCredential":"https://issuer.example/status/3"}`
)

func TestStatusEntryVectorRoundTripsAndResolvesAsStandard(t *testing.T) {
	var s CredentialStatus
	if err := json.Unmarshal([]byte(statusEntryVector), &s); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(s)
	if string(out) != statusEntryVector {
		t.Fatalf("the standard entry is not preserved:\nin : %s\nout: %s", statusEntryVector, out)
	}
	form, list, index, err := s.Resolve()
	if err != nil || form != StatusFormStandard || list != "https://issuer.example/status/3" || index != "94567" {
		t.Fatalf("Resolve = %q %q %q %v", form, list, index, err)
	}
}

func TestLegacyStatusEntryResolvesOnlyUnderItsLegacyLabel(t *testing.T) {
	var s CredentialStatus
	if err := json.Unmarshal([]byte(legacyStatusEntryVector), &s); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(s)
	if string(out) != legacyStatusEntryVector {
		t.Fatalf("a legacy entry no longer round-trips (every signature over it would fail):\n%s\n%s", legacyStatusEntryVector, out)
	}
	form, _, _, err := s.Resolve()
	if err != nil || form != StatusFormLegacyRevocationList2020 {
		t.Fatalf("a legacy entry must be labelled %q, got %q (%v)", StatusFormLegacyRevocationList2020, form, err)
	}
}

func TestStatusEntryRefusals(t *testing.T) {
	cases := map[string]string{
		"both spellings":      `{"type":"StatusList2021Entry","statusPurpose":"revocation","statusListIndex":"1","statusListCredential":"u","revocationListIndex":"1","revocationListCredential":"u"}`,
		"undefined purpose":   `{"type":"StatusList2021Entry","statusPurpose":"archive","statusListIndex":"1","statusListCredential":"u"}`,
		"missing purpose":     `{"type":"StatusList2021Entry","statusListIndex":"1","statusListCredential":"u"}`,
		"leading zero index":  `{"type":"StatusList2021Entry","statusPurpose":"revocation","statusListIndex":"01","statusListCredential":"u"}`,
		"signed index":        `{"type":"StatusList2021Entry","statusPurpose":"revocation","statusListIndex":"-1","statusListCredential":"u"}`,
		"missing list":        `{"type":"StatusList2021Entry","statusPurpose":"revocation","statusListIndex":"1"}`,
		"half a legacy entry": `{"type":"StatusList2021Entry","revocationListIndex":"1"}`,
		"no status members":   `{"type":"StatusList2021Entry"}`,
	}
	for name, raw := range cases {
		var s CredentialStatus
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, _, _, err := s.Resolve(); !errors.Is(err, ErrStatusEntry) {
			t.Errorf("PLANTED DEFECT NOT REFUSED (%s): %v", name, err)
		}
	}
	var s CredentialStatus
	if err := json.Unmarshal([]byte(`{"type":"StatusList2021Entry","statusPurpose":"revocation","statusListIndex":94567,"statusListCredential":"u"}`), &s); err == nil {
		t.Error("a numeric statusListIndex parsed; the specification makes it a string")
	}
}
