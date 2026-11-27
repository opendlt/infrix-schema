// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

import (
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"testing"
)

// A ROLE RECORD COMMITS TO EXACTLY ITS ROLE SET (infrix-core L3112): the hash is the domain tag, the count and each role length-prefixed in
// record form, so no two sets collide and the same set in any spelling or order is one record.
func TestS28coARoleRecordCommitsToExactlyItsRoleSet(t *testing.T) {
	roles := CanonicalRoles([]string{" Signer", "admin", "ADMIN", ""})
	if !slices.Equal(roles, []string{"admin", "signer"}) {
		t.Fatalf("record form %q; want [admin signer]", roles)
	}
	h := sha256.New()
	h.Write([]byte("infrix:role-record:v1"))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], 2)
	h.Write(n[:])
	for _, r := range []string{"admin", "signer"} {
		binary.BigEndian.PutUint64(n[:], uint64(len(r)))
		h.Write(n[:])
		h.Write([]byte(r))
	}
	var want [32]byte
	copy(want[:], h.Sum(nil))
	if got := RoleRecordHash(roles); got != want {
		t.Fatalf("RoleRecordHash %x; want %x", got, want)
	}
	if RoleRecordHash([]string{"ab", "c"}) == RoleRecordHash([]string{"a", "bc"}) || RoleRecordHash(nil) == RoleRecordHash([]string{""}) {
		t.Fatal("two different role sets hash alike")
	}
	if CanonicalRoleHolder(" ACC://Alice.Acme/ ") != "acc://alice.acme" {
		t.Fatalf("canonical holder %q", CanonicalRoleHolder(" ACC://Alice.Acme/ "))
	}
}
