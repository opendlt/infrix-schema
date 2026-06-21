// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package proofreceipt

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestProofReceiptSchemaIsStdlibOnly is the Tier-0 schema-leaf import fence
// (docs/extraction-plan §6). modules/infrix-schema/proofreceipt is the extractable
// proof-receipt schema (wire types + fail-closed Validate + renderers): it
// MUST depend on nothing but the Go standard library so it can be relocated to
// its own module/repo. The verifykit/releasekit-dependent converters live in
// the sibling pkg/proofreceipt precisely so this leaf stays stdlib-only. Any
// non-stdlib import here — most dangerously an `AccumulateNetwork/infrix/...`
// package (e.g. verifykit/releasekit, which would re-create the dependency the
// carve removed) — is a boundary regression and fails RED. Stdlib is
// classified as "the first path segment contains no dot".
func TestProofReceiptSchemaIsStdlibOnly(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed")
	}
	pkgDir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("read package dir %s: %v", pkgDir, err)
	}

	var sawProductionFile bool
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		sawProductionFile = true
		file, perr := parser.ParseFile(fset, filepath.Join(pkgDir, name), nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			first, _, _ := strings.Cut(path, "/")
			if strings.Contains(first, ".") {
				t.Errorf("modules/infrix-schema/proofreceipt import fence: %s imports %q, which is NOT a Go "+
					"standard-library package. The schema kernel must stay stdlib-only so it can "+
					"be extracted as a leaf module (docs/extraction-plan). Keep anything that needs "+
					"verifykit/releasekit (or any other Infrix package) in the sibling "+
					"pkg/proofreceipt converters instead.",
					name, path)
			}
		}
	}
	if !sawProductionFile {
		t.Fatalf("modules/infrix-schema/proofreceipt import fence parsed zero production files — the fence "+
			"would pass vacuously; check the package directory %s", pkgDir)
	}
}
