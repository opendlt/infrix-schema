// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidenceschema

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestEvidenceSchemaIsStdlibOnly is the Tier-0 schema-leaf import fence
// (docs/extraction-plan §6). pkg/evidenceschema is the extractable
// contract/verification kernel: it MUST depend on nothing but the Go
// standard library so it can be relocated to its own module/repo without
// dragging the governance core along. Any non-stdlib import here — most
// dangerously an `AccumulateNetwork/infrix/...` package (would re-create the
// dependency the carve removed), a `gitlab.com/accumulatenetwork/...` package,
// or a CBOR/third-party encoder — is a boundary regression and fails RED.
//
// The fence is path-free in spirit: it classifies an import as stdlib iff the
// first segment of the import path contains no dot (stdlib paths look like
// "crypto/sha256"; everything external is domain-qualified like
// "github.com/..."). Every non-test source file in the package directory is
// parsed directly, so adding a forbidden import to any production file in
// this package trips the fence regardless of which file introduced it.
func TestEvidenceSchemaIsStdlibOnly(t *testing.T) {
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
				t.Errorf("pkg/evidenceschema import fence: %s imports %q, which is "+
					"NOT a Go standard-library package. The schema kernel must stay "+
					"stdlib-only so it can be extracted as a leaf module "+
					"(docs/extraction-plan). Move whatever needs this dependency "+
					"into the core pkg/evidence runtime instead.",
					name, path)
			}
		}
	}
	if !sawProductionFile {
		t.Fatalf("pkg/evidenceschema import fence parsed zero production files — the "+
			"fence would pass vacuously; check the package directory %s", pkgDir)
	}
}
