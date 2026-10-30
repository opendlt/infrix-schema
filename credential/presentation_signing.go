// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credential

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// HOLDER BINDING THROUGH THE PROOF CONFIGURATION (W.VP.CHALLENGE.PROOFCONFIG)
//
// A holder proof used to bind the verifier's challenge by CONCATENATION: the signed bytes were
// SHA-256(presentation || challenge). Concatenation leaves the rest of the proof configuration
// (type, created, verificationMethod, proofPurpose) outside the signature, accepts a challenge
// spliced onto the end of the body by a different split of the same bytes, and has no place for the
// domain or nonce. The Data Integrity structure fixes all of that: the proof configuration is
// canonicalized on its own, hashed, and joined to the hash of the unsecured document.
//
//	signed bytes = SHA-256(canonical proof configuration) || SHA-256(presentation without its proof)
//
// The proof configuration is the object {challenge, created, domain, nonce, proofPurpose, type,
// verificationMethod}, a member omitted when empty, serialized with members in ascending key order, no
// whitespace, and strings escaped as RFC 8785 specifies (only the quotation mark, the reverse solidus
// and the control characters; everything else is raw UTF-8). Three implementations carry this
// encoding, deliberately and independently (infrix-schema, infrix-verify, and infrix core's
// pkg/zkp/vc), and one shared vector pins all of them (TestHolderSigningVector here, and the same
// literals in the other two).

// ErrChallengeMismatch is returned when the challenge a verifier expects is not the one the proof
// carries.
var ErrChallengeMismatch = errors.New("credential: the presentation proof carries a different challenge than the verifier expects")

// ProofConfigurationJSON returns the canonical serialization of a proof configuration.
func (p Proof) ProofConfigurationJSON() []byte {
	members := map[string]string{
		"challenge": p.Challenge, "created": p.Created, "domain": p.Domain, "nonce": p.Nonce,
		"proofPurpose": p.ProofPurpose, "type": p.Type, "verificationMethod": p.VerificationMethod,
	}
	keys := make([]string, 0, len(members))
	for k, v := range members {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(canonicalJSONString(k))
		b.WriteByte(':')
		b.WriteString(canonicalJSONString(members[k]))
	}
	b.WriteByte('}')
	return []byte(b.String())
}

// canonicalJSONString quotes s as RFC 8785 section 3.2.2.2 does.
func canonicalJSONString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// SigningContent returns the 64 bytes a holder signs for this presentation:
// SHA-256(canonical proof configuration) || SHA-256(presentation without its proof). The proof
// configuration is read from vp.Proof; the challenge argument is the one the VERIFIER expects, and
// it must equal the proof's challenge when the proof carries one (a proof with no challenge is
// signed over a configuration with none, so it cannot satisfy a verifier that demands one).
func (vp VerifiablePresentation) SigningContent(challenge string) ([]byte, error) {
	if vp.Proof == nil {
		return nil, errors.New("credential: the presentation has no proof configuration to bind")
	}
	cfg := *vp.Proof
	if challenge != "" {
		if cfg.Challenge != "" && cfg.Challenge != challenge {
			return nil, ErrChallengeMismatch
		}
		cfg.Challenge = challenge
	}
	unsigned := vp
	unsigned.Proof = nil
	body, err := json.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	configHash := sha256.Sum256(cfg.ProofConfigurationJSON())
	bodyHash := sha256.Sum256(body)
	return append(configHash[:], bodyHash[:]...), nil
}
