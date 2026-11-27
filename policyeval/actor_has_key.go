// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package policyeval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// KeyPageEntries are a key page's entries as actor::has_key reads them: the key hashes it lists and the delegates (key book URLs) it names. The
// node reads them from its L0 network; the verifier reads them from a key-page proof that verified under its pin.
type KeyPageEntries struct {
	KeyHashes [][]byte
	Delegates []string
}

// ResolveActorHasKey is actor::has_key(<page> [, <identity>]): TruthOperand(the key page exists AND the subject holds an entry on it), the
// operand's claim ("caller's key page?", infrix-core L3196, main's ruling 2026-11-27). The subject is the evaluation's actor, or the identity the
// optional second argument names. The subject holds an entry when an entry's delegate is the subject's own URL, when a delegate is a key book of
// the subject's own identity, or, for a lite identity, when an entry's key hash is the lite identity's key hash (HoldsEntry).
//
// It is THE body the node's eval context answers it with (infrix-core subsystemdoors.NodeEvalContext over the node's live L0 network, core's
// policy.ResolveActorHasKey is this function) and the verifier re-decides it with (ProvenRolesContext over the key pages and key books a bundle
// proves under the pin). read reads the page: its entries when it exists, (nil, nil) when its absence is known, and an error otherwise, which
// fails the rule closed rather than reading as false.
func ResolveActorHasKey(read func(page string) (*KeyPageEntries, error), actor string, args []string) (any, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return nil, errors.New("actor::has_key needs the key page it asks about")
	}
	if len(args) > 2 {
		return nil, fmt.Errorf("actor::has_key takes a key page and an optional identity, not %d arguments", len(args))
	}
	subject := strings.TrimSpace(actor)
	if len(args) == 2 {
		subject = strings.TrimSpace(args[1])
		if _, _, err := splitAccURL(subject); err != nil {
			return nil, fmt.Errorf("actor::has_key: the identity argument %q is malformed: %w", args[1], err)
		}
	}
	if subject == "" {
		return nil, errors.New("actor::has_key asks about the evaluation's actor, and this evaluation has none")
	}
	if read == nil {
		return nil, errors.New("actor::has_key: no L0 network to read the key page from")
	}
	page := strings.TrimSpace(args[0])
	entries, err := read(page)
	if err != nil {
		return nil, fmt.Errorf("actor::has_key(%q): %w", page, err)
	}
	if entries == nil {
		return TruthOperand(false), nil
	}
	return TruthOperand(HoldsEntry(*entries, subject)), nil
}

// HoldsEntry reports whether identity holds an entry on a page with these entries: a delegate is the identity's own URL, a delegate is a key book
// of the identity's own ADI, or (a lite identity) an entry's key hash is the lite identity's key hash.
func HoldsEntry(entries KeyPageEntries, identity string) bool {
	authority, path, err := splitAccURL(identity)
	if err != nil {
		return false
	}
	for _, d := range entries.Delegates {
		da, dp, err := splitAccURL(d)
		if err != nil {
			continue
		}
		if da == authority && (dp == path || path == "") {
			return true
		}
	}
	if keyHash, ok := liteIdentityKeyHash(authority); ok && path == "" {
		for _, h := range entries.KeyHashes {
			if len(h) >= len(keyHash) && bytes.Equal(h[:len(keyHash)], keyHash) {
				return true
			}
		}
	}
	return false
}

// splitAccURL splits an acc:// URL into its authority and path (both lower case, the path without leading or trailing slashes).
func splitAccURL(u string) (authority, path string, err error) {
	s := strings.ToLower(strings.TrimSpace(u))
	if !strings.HasPrefix(s, "acc://") {
		return "", "", fmt.Errorf("%q is not an acc:// URL", u)
	}
	s = strings.TrimPrefix(s, "acc://")
	authority, path, _ = strings.Cut(s, "/")
	if authority == "" || strings.ContainsAny(authority, " ?#@") {
		return "", "", fmt.Errorf("%q names no identity", u)
	}
	return authority, strings.Trim(path, "/"), nil
}

// liteIdentityKeyHash is the key-hash prefix a lite identity's authority encodes (Accumulate's lite address: the hex of the key hash's first 20
// bytes followed by the hex of the last 4 bytes of the SHA-256 of that hex), and whether the authority is one.
func liteIdentityKeyHash(authority string) ([]byte, bool) {
	if len(authority) != 48 {
		return nil, false
	}
	b, err := hex.DecodeString(authority)
	if err != nil {
		return nil, false
	}
	sum := sha256.Sum256([]byte(authority[:40]))
	if !bytes.Equal(b[20:], sum[28:]) {
		return nil, false
	}
	return b[:20], true
}

// ErrAbsenceNotProvable is why a key page the bundle proves neither present nor absent is not answered offline: a page is proven present by its
// key-page proof (and its entries then answer), and absent when the bundle proves its key book and the page's index is past the book's page
// count; an absent identity or an absent key book has no proof at all, because Accumulate's BPT receipts prove membership only (a receipt starts
// at the leaf's value and carries sibling hashes; a missing key has no leaf and no receipt form).
var ErrAbsenceNotProvable = errors.New("the bundle proves neither the key page nor, through its key book's page count, its absence, and an absent identity or key book is not provable from Accumulate's receipts")

// ProvenKeyPage is the read of ResolveActorHasKey over what a bundle proves under the pin: pages (page URL, lower case) whose key-page proof
// verified answer their entries; books (key book URL, lower case) whose state proof verified answer a page past their page count as absent;
// every other page is ErrAbsenceNotProvable.
func ProvenKeyPage(pages map[string]KeyPageEntries, books map[string]uint64) func(string) (*KeyPageEntries, error) {
	return func(page string) (*KeyPageEntries, error) {
		key := strings.ToLower(strings.Trim(strings.TrimSpace(page), "/"))
		if e, ok := pages[key]; ok {
			return &e, nil
		}
		if book, index, ok := PageBookAndIndex(key); ok {
			if count, proven := books[book]; proven && index > count {
				return nil, nil
			}
		}
		return nil, ErrAbsenceNotProvable
	}
}

// PageBookAndIndex splits a key page URL (<key book>/<n>, n from 1) into its book URL (lower case) and its index.
func PageBookAndIndex(page string) (string, uint64, bool) {
	s := strings.ToLower(strings.Trim(strings.TrimSpace(page), "/"))
	i := strings.LastIndex(s, "/")
	if i < 0 || !strings.HasPrefix(s, "acc://") || i <= len("acc://") {
		return "", 0, false
	}
	n, err := strconv.ParseUint(s[i+1:], 10, 64)
	if err != nil || n == 0 {
		return "", 0, false
	}
	return s[:i], n, true
}
