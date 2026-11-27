// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strings"
)

// THE ROLE REGISTRY UNDER THE NODE STATE ROOT (infrix-core L3112, brief 28bu row 2 (a); 28co).
//
// A policy that reads actor::role is decided over the node's role registry, which the contract state proofs (StorageInclusionProof,
// AccountInclusionProof) never covered. The node commits the registry as one more leaf of its sealed node state tree: the leaf of the account
// RoleRegistryAccount, whose root is a sealed tree (the node state tree's own hashing: leaves sorted by holder, positional, an odd last node
// carried up, sealed with its leaf count) over one leaf per holder that holds at least one role in the global scope:
//
//	role leaf(holder, roles) = node-tree leaf(holder, RoleRecordHash(roles))
//	RoleRecordHash(roles)    = H("infrix:role-record:v1" || be64(n) || for each role in order: be64(len role) || role)
//
// Holder is the canonical identity (lower case, no trailing slash); roles are lower case, sorted, each once. A holder with no leaf holds no
// role globally. A RoleRecordProof proves either the holder's leaf (Held) or that no leaf names it: the two adjacent leaves around it (Before,
// After: positional proofs at consecutive indexes of the same tree), or the one at an end of the tree, or the empty tree (Leaves 0). A verifier
// recomputes all of it against the bundle's StateRoot; nothing here is credited because the node wrote it.

// RoleRegistryAccount is the account whose leaf in the sealed node state tree is the role registry's root.
const RoleRegistryAccount = "infrix:system/role-registry"

// RoleRecordTag domain-separates a role record's hash.
const RoleRecordTag = "infrix:role-record:v1"

// RoleRegistryProof proves what roles holders held in the global scope at the bundle's StateRoot.
type RoleRegistryProof struct {
	// RegistryRoot is the role registry's sealed root; Account proves it is RoleRegistryAccount's leaf in StateRoot.
	RegistryRoot [32]byte              `json:"registryRoot"`
	Account      AccountInclusionProof `json:"account"`
	// Leaves is the registry tree's leaf count, which every record's positional proof is against.
	Leaves  uint64            `json:"leaves"`
	Records []RoleRecordProof `json:"records"`
}

// RoleRecordProof proves the global roles of one holder: its leaf (Held), or no leaf for it (Before and/or After, or an empty registry).
type RoleRecordProof struct {
	Holder string          `json:"holder"`
	Held   *RoleRecordLeaf `json:"held,omitempty"`
	Before *RoleRecordLeaf `json:"before,omitempty"`
	After  *RoleRecordLeaf `json:"after,omitempty"`
}

// RoleRecordLeaf is one leaf of the registry tree with its positional path.
type RoleRecordLeaf struct {
	Holder   string     `json:"holder"`
	Roles    []string   `json:"roles"`
	Index    uint64     `json:"index"`
	Siblings [][32]byte `json:"siblings"`
}

// CanonicalRoleHolder is the holder form the registry tree is keyed by: lower case, surrounding space and trailing slashes removed.
func CanonicalRoleHolder(holder string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(holder)), "/")
}

// CanonicalRoles is a role set in record form: lower case, sorted, each once, empty names dropped.
func CanonicalRoles(roles []string) []string {
	seen := make(map[string]bool, len(roles))
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		r = strings.ToLower(strings.TrimSpace(r))
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// RoleRecordHash is the hash of a holder's role set (in record form) that the holder's leaf commits to.
func RoleRecordHash(roles []string) [32]byte {
	h := sha256.New()
	var n [8]byte
	h.Write([]byte(RoleRecordTag))
	binary.BigEndian.PutUint64(n[:], uint64(len(roles)))
	h.Write(n[:])
	for _, r := range roles {
		binary.BigEndian.PutUint64(n[:], uint64(len(r)))
		h.Write(n[:])
		h.Write([]byte(r))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
