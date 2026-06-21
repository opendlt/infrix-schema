// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package intent

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestIntentSchemaIsStdlibOnly is the Tier-0 schema-leaf import fence
// (docs/extraction-plan §6). modules/infrix-schema/intent is the extractable intent
// goal/type vocabulary: it MUST depend on nothing but the Go standard library
// (in fact it currently imports nothing at all) so it can be relocated to its
// own module/repo without pulling the governance core along. Any non-stdlib
// import here — most dangerously an `AccumulateNetwork/infrix/...` package —
// is a boundary regression and fails RED. Stdlib is classified as "the first
// path segment contains no dot" (stdlib paths look like "encoding/json";
// external ones are domain-qualified like "github.com/...").
func TestIntentSchemaIsStdlibOnly(t *testing.T) {
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
				t.Errorf("modules/infrix-schema/intent import fence: %s imports %q, which is NOT a Go "+
					"standard-library package. The schema kernel must stay stdlib-only so it "+
					"can be extracted as a leaf module (docs/extraction-plan). Move whatever "+
					"needs this dependency into pkg/intent (the runtime side) instead.",
					name, path)
			}
		}
	}
	if !sawProductionFile {
		t.Fatalf("modules/infrix-schema/intent import fence parsed zero production files — the fence would "+
			"pass vacuously; check the package directory %s", pkgDir)
	}
}
