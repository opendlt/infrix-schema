// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credential

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// THE WIRE SPELLING OF AN Ed25519 VERIFICATION KEY.
//
// An Ed25519VerificationKey2020 (and a Multikey) publishes its key as publicKeyMultibase:
// the multibase prefix "z" (base58btc) followed by base58btc(0xed 0x01 || 32 key bytes). It was
// "m" + base64 of the bare key before Wave D1d, a spelling no registry describes. infrix-core,
// infrix-schema (here) and infrix-verify each implement the encoding on their own on purpose,
// and each pins the same vector (the W3C Ed25519Signature2020 test key), so one of them changing
// the spelling fails the other two.

var multikeyEd25519Prefix = [2]byte{0xed, 0x01}

// ErrMultikey is returned for a publicKeyMultibase that is not z + base58btc(0xed01 || 32 bytes).
var ErrMultikey = errors.New("credential: publicKeyMultibase is not an Ed25519 Multikey (z + base58btc of 0xed01 and 32 key bytes)")

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(in []byte) string {
	n := new(big.Int).SetBytes(in)
	base, mod := big.NewInt(58), new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for _, b := range in {
		if b != 0 {
			break
		}
		out = append(out, base58Alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58Decode(in string) ([]byte, error) {
	n := new(big.Int)
	base := big.NewInt(58)
	for _, r := range in {
		d := strings.IndexRune(base58Alphabet, r)
		if d < 0 {
			return nil, fmt.Errorf("%w: %q is outside the base58btc alphabet", ErrMultikey, r)
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(d)))
	}
	out := n.Bytes()
	zeros := 0
	for zeros < len(in) && in[zeros] == base58Alphabet[0] {
		zeros++
	}
	return append(make([]byte, zeros), out...), nil
}

// EncodeEd25519Multikey spells a 32-byte Ed25519 public key as publicKeyMultibase.
func EncodeEd25519Multikey(pub []byte) (string, error) {
	if len(pub) != 32 {
		return "", fmt.Errorf("%w: key is %d bytes", ErrMultikey, len(pub))
	}
	return "z" + base58Encode(append(multikeyEd25519Prefix[:], pub...)), nil
}

// DecodeEd25519Multikey is the inverse. It refuses any other multibase base, multicodec or length
// (including the earlier "m"+base64 spelling) instead of guessing.
func DecodeEd25519Multikey(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "z") {
		return nil, fmt.Errorf("%w: %q has no z prefix", ErrMultikey, s)
	}
	raw, err := base58Decode(s[1:])
	if err != nil {
		return nil, err
	}
	if len(raw) != 34 || raw[0] != multikeyEd25519Prefix[0] || raw[1] != multikeyEd25519Prefix[1] {
		return nil, fmt.Errorf("%w: %q decodes to %d bytes with prefix %x", ErrMultikey, s, len(raw), raw[:min(2, len(raw))])
	}
	return raw[2:], nil
}
