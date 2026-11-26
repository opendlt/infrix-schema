// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

// THE STATE PROOFS A BUNDLE CARRIES (brief 28bd phase 2b, L2992; the native proof plan's L1 and L2).
//
// The node's state root is a sealed binary Merkle tree over every deployed contract's committed-state root (infrix-core pkg/noderoot), and a
// contract's root is a binary Merkle tree over its committed key/value pairs. A bundle that claims what a contract held carries, for each
// claimed key, a StorageInclusionProof (L1: the key holds the value in the contract root) and, for each contract, an AccountInclusionProof
// (L2: the contract root is the contract's leaf in the node state root, which is the bundle's StateRoot, the root BundleHash commits to and
// the L3 batch therefore binds). A verifier recomputes both itself; nothing here is credited because the node wrote it.

// StorageInclusionProof proves Key holds Value in the committed state whose root is ContractRoot: the key's leaf folded up KeyPath.
type StorageInclusionProof struct {
	Contract     string     `json:"contract"`
	Key          string     `json:"key"`
	Value        []byte     `json:"value"`
	KeyPath      [][32]byte `json:"keyPath"`
	ContractRoot [32]byte   `json:"contractRoot"`
}

// AccountInclusionProof proves the contract's committed-state root is its leaf in the sealed node state root: the leaf at Index of a
// Leaves-leaf tree, with Siblings the path up.
type AccountInclusionProof struct {
	Contract     string     `json:"contract"`
	ContractRoot [32]byte   `json:"contractRoot"`
	Index        uint64     `json:"index"`
	Leaves       uint64     `json:"leaves"`
	Siblings     [][32]byte `json:"siblings"`
}
