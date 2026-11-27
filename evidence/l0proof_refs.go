// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
)

// THE ACCUMULATE PROOFS A BUNDLE CARRIES (the native proof plan, phases 5 and 7; brief 28bh).
//
// Each is carried in the exact JSON encoding of the verifier's own type, so the schema stays free of the verifier and a verifier decodes exactly what the
// capture service wrote:
//
//   - EvidenceBundle.L0Proof: an infrix-verify l0proof.L0ProofChain proving the bundle's batch root (AnchorInclusion.BatchRoot) is the single data item of a
//     WriteData Accumulate executed on the anchor account, carried to a Directory header certified from the verifier's pin (L4, source embedded-proof).
//   - EvidenceBundle.KeyPageProofs: infrix-verify govproof.KeyPageProof values, one per key page an approval names, each proving the page's keys and
//     threshold at a certified partition block (G1), in one of two forms (KeyPageProofFormOf): the page with its partition ledger in one BPT root,
//     captured at execution time (the ledger states the block and its time), or the page at a BPT root its partition anchored on the Directory,
//     bound by the partition's BlockValidatorAnchor (core L3168: the capture after a restart or on an idle partition, with no network activity);
//     there the block is credited exactly as that anchor states it and the block time is named unproven, never claimed.
//   - EvidenceBundle.GovernanceExecution: an infrix-verify govproof.GovernanceExecution proving Accumulate executed the M-of-N approval of the plan for this
//     bundle under the app's governance page (G2).
//
// None of them is proof because the node wrote it: a verifier recomputes every link, refuses any proof captured under an incarnation other than its own
// pin, and credits nothing when a link fails.

// Forms of an embedded key-page proof (infrix-verify govproof FormLedger and FormDirectoryRoot, which the verifier reports; these name the same
// forms for a consumer that reads a bundle without the verifier).
const (
	KeyPageProofFormLedger        = "page_with_ledger"
	KeyPageProofFormDirectoryRoot = "page_at_directory_root"
)

// KeyPageProofFormOf names the form an embedded key-page proof is carried in: the directory-root form carries the partition's anchor
// ("partitionAnchor") and no partition ledger, the ledger form a "ledgerState". It reads the shape only: it proves nothing, and a verifier
// credits a proof only after checking every link. A proof carrying both, or neither, is refused by name.
func KeyPageProofFormOf(raw json.RawMessage) (string, error) {
	var shape struct {
		LedgerState     json.RawMessage `json:"ledgerState"`
		PartitionAnchor json.RawMessage `json:"partitionAnchor"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		return "", fmt.Errorf("evidence: the key-page proof is not a JSON object: %w", err)
	}
	present := func(m json.RawMessage) bool { return len(m) > 0 && string(m) != "null" }
	switch l, a := present(shape.LedgerState), present(shape.PartitionAnchor); {
	case l && a:
		return "", errors.New("evidence: the key-page proof carries both a partition ledger and a partition anchor; a key-page proof takes one form")
	case a:
		return KeyPageProofFormDirectoryRoot, nil
	case l:
		return KeyPageProofFormLedger, nil
	default:
		return "", errors.New("evidence: the key-page proof carries neither a partition ledger nor a partition anchor; neither its partition nor its block is proven")
	}
}
