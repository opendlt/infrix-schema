// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

// THE ACCUMULATE PROOFS A BUNDLE CARRIES (the native proof plan, phases 5 and 7; brief 28bh).
//
// Each is carried in the exact JSON encoding of the verifier's own type, so the schema stays free of the verifier and a verifier decodes exactly what the
// capture service wrote:
//
//   - EvidenceBundle.L0Proof: an infrix-verify l0proof.L0ProofChain proving the bundle's batch root (AnchorInclusion.BatchRoot) is the single data item of a
//     WriteData Accumulate executed on the anchor account, carried to a Directory header certified from the verifier's pin (L4, source embedded-proof).
//   - EvidenceBundle.KeyPageProofs: infrix-verify govproof.KeyPageProof values, one per key page an approval names, each proving the page's keys and
//     threshold at a certified partition block, captured at execution time (G1).
//   - EvidenceBundle.GovernanceExecution: an infrix-verify govproof.GovernanceExecution proving Accumulate executed the M-of-N approval of the plan for this
//     bundle under the app's governance page (G2).
//
// None of them is proof because the node wrote it: a verifier recomputes every link, refuses any proof captured under an incarnation other than its own
// pin, and credits nothing when a link fails.
