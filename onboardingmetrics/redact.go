// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package onboardingmetrics

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var (
	// Accumulate account URLs (acc://...) — redacted by default.
	reAccountURL = regexp.MustCompile(`(?i)acc://[A-Za-z0-9._\-/]+`)
	// Long hex runs (full hashes, signatures, private keys) — 32+ hex chars.
	reLongHex = regexp.MustCompile(`(?i)\b(0x)?[0-9a-f]{32,}\b`)
	// Field names that indicate a secret if they ever appear in a value.
	reSecretMarker = regexp.MustCompile(`(?i)(private[_-]?key|privkey|secret|seed|mnemonic|passphrase|password|begin [a-z ]*private key)`)
)

// HashSessionID returns a stable, non-reversible session identifier: the first
// 16 hex chars of SHA-256 of the raw id. Raw session ids are never stored.
func HashSessionID(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "s_" + hex.EncodeToString(sum[:])[:16]
}

// IsSensitive reports whether a string carries material that must never be
// stored: a private-key marker or a long hex run (a key/full hash). Account
// URLs are sensitive-by-policy but redactable, so they are handled separately.
func IsSensitive(s string) bool {
	if s == "" {
		return false
	}
	return reSecretMarker.MatchString(s) || reLongHex.MatchString(s)
}

// scrub redacts account URLs and long hashes from a free string.
func scrub(s string) string {
	if s == "" {
		return s
	}
	s = reAccountURL.ReplaceAllString(s, "[redacted-account]")
	s = reLongHex.ReplaceAllString(s, "[redacted-hash]")
	return s
}

// stringFields returns the addressable free-text fields of an event that could
// conceivably carry caller-supplied content. Enumerated fields (mode, result,
// proofLevel, governanceLevel) are closed sets and not scrubbed.
func freeTextFields(e *Event) []*string {
	return []*string{&e.Event, &e.Command, &e.Persona, &e.ErrorCode}
}

// Redact returns a redacted copy of e: account URLs and long hashes are scrubbed
// from free-text fields and Redacted is set true. The session id is assumed
// already hashed (see HashSessionID). This is the default form stored on disk
// and the only form a hosted endpoint accepts.
func Redact(e Event) Event {
	cp := e
	for _, f := range freeTextFields(&cp) {
		*f = scrub(*f)
	}
	cp.Redacted = true
	return cp
}

// SensitiveField scans an event for any field still carrying must-never-store
// material (a private key or a long hash that scrubbing would not have been
// asked to handle). It returns the offending field name and true when found.
// The hosted endpoint uses this to REJECT non-redacted sensitive submissions.
func SensitiveField(e *Event) (string, bool) {
	checks := map[string]string{
		"event":     e.Event,
		"command":   e.Command,
		"persona":   e.Persona,
		"errorCode": e.ErrorCode,
		"sessionId": e.SessionID,
	}
	for name, val := range checks {
		if IsSensitive(val) {
			return name, true
		}
		if strings.Contains(strings.ToLower(val), "acc://") {
			return name, true
		}
	}
	return "", false
}
