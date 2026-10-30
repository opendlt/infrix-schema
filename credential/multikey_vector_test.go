// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credential

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// The shared vector: the Ed25519Signature2020 test key of the W3C CCG specification
// (https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/ section 4), published
// both as publicKeyBase58 (keypair_0) and as publicKeyMultibase (keypair_1). The same three values are pinned
// in infrix-core (pkg/did) and infrix-verify (credverify).
const (
	multikeyVectorBase58    = "dbDmZLTWuEYYZNHFLKLoRkEX4sZykkSLNQLXvMUyMB1"
	multikeyVectorMultibase = "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"
	multikeyVectorKeyHex    = "095f9a1a595dde755d82786864ad03dfa5a4fbd68832566364e2b65e13cc9e44"
)

func TestMultikeyVector(t *testing.T) {
	raw, err := base58Decode(multikeyVectorBase58)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(raw) != multikeyVectorKeyHex {
		t.Fatalf("the W3C publicKeyBase58 decodes to %x, the pinned vector is %s", raw, multikeyVectorKeyHex)
	}
	got, err := DecodeEd25519Multikey(multikeyVectorMultibase)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("DecodeEd25519Multikey(%s) = %x, %v; want %x", multikeyVectorMultibase, got, err, raw)
	}
	mb, err := EncodeEd25519Multikey(raw)
	if err != nil || mb != multikeyVectorMultibase {
		t.Fatalf("EncodeEd25519Multikey = %s, %v; want %s", mb, err, multikeyVectorMultibase)
	}
}

func TestMultikeyRefusals(t *testing.T) {
	for name, in := range map[string]string{
		"base64 spelling":    "mAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"no prefix":          multikeyVectorMultibase[1:],
		"wrong multicodec":   "z" + base58Encode(append([]byte{0xe7, 0x01}, make([]byte, 32)...)),
		"short key":          "z" + base58Encode(append([]byte{0xed, 0x01}, make([]byte, 31)...)),
		"outside alphabet 0": "z6Mk0f5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
	} {
		if _, err := DecodeEd25519Multikey(in); !errors.Is(err, ErrMultikey) {
			t.Errorf("PLANTED DEFECT NOT REFUSED (%s): %v", name, err)
		}
	}
	if _, err := EncodeEd25519Multikey(make([]byte, 31)); !errors.Is(err, ErrMultikey) {
		t.Errorf("a 31-byte key was encoded: %v", err)
	}
}
