// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shared vector (testdata/directory-root.json, byte-identical to infrix-verify govproof/testdata/simulator/directory-root.json, which the
// verifier's l0proofref writes and verifies, and to core's copy): a page proven at a Directory-recorded root is named in that form, travels in a
// bundle outside BundleHash, and a proof in both forms or in neither is refused by name (core L3168).
func TestS28clTheDirectoryRootKeyPageProofVectorIsNamedInItsForm(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "directory-root.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Proof json.RawMessage `json:"proof"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	form, err := KeyPageProofFormOf(v.Proof)
	if err != nil || form != KeyPageProofFormDirectoryRoot {
		t.Fatalf("the vector's form is %q (%v), want %q", form, err, KeyPageProofFormDirectoryRoot)
	}
	b := &EvidenceBundle{ID: "ev-i", IntentID: "i", PlanID: "p", OutcomeID: "o", Level: "standard"}
	before, err := b.ComputeBundleHash()
	if err != nil {
		t.Fatal(err)
	}
	b.KeyPageProofs = []json.RawMessage{v.Proof}
	if after, err := b.ComputeBundleHash(); err != nil || after != before {
		t.Fatalf("embedding the directory-root proof changed BundleHash (%v)", err)
	}
	if f, err := KeyPageProofFormOf(json.RawMessage(`{"ledgerState":{"mainState":"00"}}`)); err != nil || f != KeyPageProofFormLedger {
		t.Fatalf("the ledger form is named %q (%v)", f, err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(v.Proof, &m); err != nil {
		t.Fatal(err)
	}
	m["ledgerState"] = json.RawMessage(`{"mainState":"00"}`)
	both, _ := json.Marshal(m)
	if _, err := KeyPageProofFormOf(both); err == nil || !strings.Contains(err.Error(), "one form") {
		t.Fatalf("a proof in both forms is named %v; want it refused", err)
	}
	delete(m, "ledgerState")
	delete(m, "partitionAnchor")
	neither, _ := json.Marshal(m)
	if _, err := KeyPageProofFormOf(neither); err == nil || !strings.Contains(err.Error(), "neither its partition nor its block") {
		t.Fatalf("a proof in neither form is named %v; want it refused", err)
	}
}
