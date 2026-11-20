// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package intent

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// A requester's metadata is a bounded JSON object of string keys and JSON values, distinct from the node's attribution Metadata, and it rides
// in the intent's own JSON under requesterMetadata.

func TestRequesterMetadataIsABoundedJSONObject(t *testing.T) {
	m, err := ParseRequesterMetadata([]byte(` {"ref":"order-7","n":3,"tags":["a","b"],"nested":{"ok":true},"none":null} `))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"ref": "order-7", "n": float64(3), "tags": []any{"a", "b"}, "nested": map[string]any{"ok": true}, "none": nil}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("got %#v", m)
	}
	for _, empty := range []string{"", "  ", "{}"} {
		if m, err := ParseRequesterMetadata([]byte(empty)); err != nil || m != nil {
			t.Fatalf("%q is no metadata: %v %v", empty, m, err)
		}
	}

	for raw, want := range map[string]string{
		`"text"`:   "not a string",
		`[1,2]`:    "not an array",
		`true`:     "not a boolean",
		`null`:     "not null",
		`42`:       "not a number",
		`{"a":1}x`: "data after its JSON object",
		`{"":1}`:   "key is empty",
		`{"a":`:    "not a well-formed JSON object",
	} {
		_, err := ParseRequesterMetadata([]byte(raw))
		if !errors.Is(err, ErrRequesterMetadata) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want a refusal naming %q, got %v", raw, want, err)
		}
	}

	longKey := `{"` + strings.Repeat("k", MaxRequesterMetadataKeyBytes+1) + `":1}`
	if _, err := ParseRequesterMetadata([]byte(longKey)); !errors.Is(err, ErrRequesterMetadata) || !strings.Contains(err.Error(), "over the 128-byte bound") {
		t.Fatalf("an over-long key: %v", err)
	}
	// The bound is on the compact encoding, measured exactly: at the bound it is accepted, one byte over it is refused.
	pad := MaxRequesterMetadataBytes - len(`{"v":""}`)
	at := `{"v":"` + strings.Repeat("x", pad) + `"}`
	if _, err := ParseRequesterMetadata([]byte(at)); err != nil {
		t.Fatalf("metadata of exactly %d bytes is within the bound: %v", MaxRequesterMetadataBytes, err)
	}
	over := `{"v":"` + strings.Repeat("x", pad+1) + `"}`
	if _, err := ParseRequesterMetadata([]byte(over)); !errors.Is(err, ErrRequesterMetadata) || !strings.Contains(err.Error(), "over the 4096-byte bound") {
		t.Fatalf("metadata one byte over the bound: %v", err)
	}
}

func TestRequesterMetadataRidesInTheIntentApartFromTheNodesMetadata(t *testing.T) {
	in := Intent{ID: "i", Metadata: map[string]string{"standing.intentId": "s"}, RequesterMetadata: map[string]any{"ref": "order-7"}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"requesterMetadata":{"ref":"order-7"}`) || !strings.Contains(string(raw), `"metadata":{"standing.intentId":"s"}`) {
		t.Fatalf("the intent encodes as %s", raw)
	}
	var back Intent
	if err := json.Unmarshal(raw, &back); err != nil || !reflect.DeepEqual(back.RequesterMetadata, in.RequesterMetadata) || !reflect.DeepEqual(back.Metadata, in.Metadata) {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	if raw, _ := json.Marshal(Intent{ID: "i"}); strings.Contains(string(raw), "requesterMetadata") {
		t.Fatalf("an intent with no requester metadata states none: %s", raw)
	}
}

// TestRequesterMetadataIsMeasuredAsAClientMeasuresIt pins the measured encoding the SDKs mirror: '<', '>' and '&' count as one byte each (no HTML
// escaping), U+2028 counts as six. The vector is repeated in infrix-sdk-js (requesterMetadata.test.ts) and infrix-crates (requester_metadata tests).
func TestRequesterMetadataIsMeasuredAsAClientMeasuresIt(t *testing.T) {
	// {"v":"<&>"} is 11 bytes unescaped; padded with x to exactly the bound, it is accepted.
	pad := MaxRequesterMetadataBytes - len(`{"v":"<&>"}`)
	at := map[string]any{"v": "<&>" + strings.Repeat("x", pad)}
	if err := ValidateRequesterMetadata(at); err != nil {
		t.Fatalf("'<', '&' and '>' must count one byte each: %v", err)
	}
	// U+2028 is written as   (six bytes): one in place of three x's of the bound is three bytes over.
	sep := map[string]any{"v": "<&> " + strings.Repeat("x", pad-3)}
	err := ValidateRequesterMetadata(sep)
	if !errors.Is(err, ErrRequesterMetadata) || !strings.Contains(err.Error(), "encodes to 4099 bytes") {
		t.Fatalf("U+2028 must count six bytes: %v", err)
	}
}
