// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package policyeval

import (
	"errors"
	"fmt"
	"strings"
)

// ResolveActorHasKey is actor::has_key(<account>): TruthOperand(the account, a key page URL, exists on the L0 network). It is THE body the node's
// eval context answers it with (infrix-core subsystemdoors.NodeEvalContext over the node's live L0 network, core's policy.ResolveActorHasKey is
// this function) and the verifier re-decides it with (ProvenRolesContext over the key pages the bundle proves under the pin, infrix-core L3196).
// exists reads the account: (true, nil) when it exists, (false, nil) when its absence is known, and an error otherwise, which fails the rule
// closed rather than reading as false.
func ResolveActorHasKey(exists func(account string) (bool, error), args []string) (any, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return nil, errors.New("actor::has_key needs the account it asks about (a key page URL)")
	}
	if exists == nil {
		return nil, errors.New("actor::has_key: no L0 network to read the account from")
	}
	ok, err := exists(strings.TrimSpace(args[0]))
	if err != nil {
		return nil, fmt.Errorf("actor::has_key(%q): %w", args[0], err)
	}
	return TruthOperand(ok), nil
}

// ErrAbsenceNotProvable is why an account the bundle proves no key page for is not answered offline: Accumulate's BPT receipts prove
// membership only (a receipt starts at the leaf's value and carries sibling hashes; a missing key has no leaf and no receipt form), so the
// absence of an account cannot be proven against the pin, and actor::has_key answers "false" only on the node.
var ErrAbsenceNotProvable = errors.New("the bundle proves no key page for the account, and an account's absence is not provable from Accumulate's receipts")

// ProvenPageExists is the exists reader of ResolveActorHasKey over the key pages a bundle proves (page URL, lower case): true for a proven page,
// ErrAbsenceNotProvable for any other.
func ProvenPageExists(pages map[string]bool) func(string) (bool, error) {
	return func(account string) (bool, error) {
		if pages[strings.ToLower(strings.TrimSpace(account))] {
			return true, nil
		}
		return false, ErrAbsenceNotProvable
	}
}
