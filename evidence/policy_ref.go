// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

// PolicyRef is a content-addressed policy: Content is the canonical policy document (infrix-schema policyeval.EncodeDocument) and Hash is
// its SHA-256 (policyeval.ContentHash). A verifier refuses a PolicyRef whose content does not hash to Hash (native proof plan BD-06).
//
// Content is bytes (base64 in JSON), never embedded JSON: the bundle's canonical encoding re-encodes embedded JSON (it sorts object keys),
// which would change the bytes the hash addresses.
type PolicyRef struct {
	Hash    [32]byte `json:"hash"`
	Content []byte   `json:"content"`
}

// PolicySubject is what a goal policy was decided over at intent admission, the fields of policyeval.Subject (this package stays
// stdlib-only, so it mirrors them). Amount is absent when the goal stated none.
type PolicySubject struct {
	Actor       string   `json:"actor"`
	Contract    string   `json:"contract,omitempty"`
	Function    string   `json:"function,omitempty"`
	BlockHeight uint64   `json:"blockHeight"`
	Amount      *float64 `json:"amount,omitempty"`
}

// PolicyEvaluation is one decision a plan was governed under, in re-evaluable form: the policy type and scope it was decided at, the
// content-addressed policy in force, and the subject. It carries no decision: the verifier decides.
type PolicyEvaluation struct {
	PolicyType string        `json:"policyType"`
	ScopeKey   string        `json:"scopeKey,omitempty"`
	Policy     PolicyRef     `json:"policy"`
	Subject    PolicySubject `json:"subject"`
}
