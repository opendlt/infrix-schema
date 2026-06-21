// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidenceschema

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
)

// Gap 8 sub-gap B closure: deterministic canonical JSON for portable
// evidence packages.
//
// The Go standard library's json.Marshal already orders struct fields
// in source order and sorts map[string]X keys lexicographically, which
// is sufficient for byte-stable hashing of fixed schemas. For arbitrary
// any/interface inputs that contain nested maps the sort guarantee
// transitively applies. canonicalJSON re-marshals through this path so
// the resulting bytes are reproducible across runs and Go versions and
// match the rules used by external verifiers per PORTABLE_SPEC.md.
//
// The output is NOT a full RFC 8785 (JCS) implementation — it does not
// re-format numbers into the ECMAScript canonical form. Bundles use
// integer fields only; floats appear in DriftAnalysisRef but those
// values are derived from divisions of integer gas counts and are
// expected to round-trip identically across implementations. If a
// portable verifier in another language disagrees on number formatting
// the spec MUST be tightened before declaring multi-language portability.

// CanonicalJSON returns a deterministic JSON encoding suitable for
// use as a hashing input. For struct values the result is identical to
// json.Marshal. For map values keys are sorted lexicographically. For
// any other input, the value is round-tripped through map normalization
// to guarantee key ordering in nested maps.
func CanonicalJSON(v any) ([]byte, error) {
	// Round-trip through json.Marshal -> arbitrary -> sortedMarshal so
	// every map nested inside an interface{} is normalized.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeCanonical emits a deterministic encoding of v to buf. Maps are
// emitted with keys in lexicographic order. Slices preserve order.
// Scalars are emitted via json.Marshal so number formatting matches the
// stdlib encoder.
func writeCanonical(buf *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []any:
		buf.WriteByte('[')
		for i, e := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		raw, err := json.Marshal(val)
		if err != nil {
			return fmt.Errorf("canonical: marshal scalar %T: %w", val, err)
		}
		buf.Write(raw)
		return nil
	}
}

// Sha256Sum32 is the [32]byte form of sha256.Sum256 used throughout
// the evidence package.
func Sha256Sum32(data []byte) [32]byte {
	return sha256.Sum256(data)
}
