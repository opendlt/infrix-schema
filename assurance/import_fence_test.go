// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package assurance

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestAssuranceSchemaIsStdlibOnly is the Tier-1 schema-leaf import fence
// (docs/extraction-plan §6, M4.3). infrix-schema/assurance is the assurance
// ladder vocabulary (proof/governance/IU levels + ClassFor): it MUST depend on
// nothing but the Go standard library so the verifier can classify a proof's
// depth without dragging the runtime proof engine (anchor/state) — or anything
// else from the monorepo — into its dependency graph. Any non-stdlib import
// here is a boundary regression and fails RED. Stdlib is classified as "the
// first path segment contains no dot".
func TestAssuranceSchemaIsStdlibOnly(t *testing.T) {
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
				t.Errorf("infrix-schema/assurance import fence: %s imports %q, which is NOT a Go "+
					"standard-library package. The assurance ladder must stay stdlib-only so it can "+
					"be extracted as a leaf (docs/extraction-plan). Keep anything that needs anchor/"+
					"state (the proof engine) or any other Infrix package in the core pkg/assurance.",
					name, path)
			}
		}
	}
	if !sawProductionFile {
		t.Fatalf("infrix-schema/assurance import fence parsed zero production files — the fence "+
			"would pass vacuously; check the package directory %s", pkgDir)
	}
}
