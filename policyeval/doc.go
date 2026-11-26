// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package policyeval is the ONE body of Infrix's deterministic policy evaluator: the expression language (lexer, parser, compiler), the
// bytecode VM, the first-match decision rule, the content-addressed policy document, and the subject a goal policy is decided over at
// intent admission. The node (infrix-core pkg/policy, which aliases this package) and the canonical verifier (infrix-verify verifykit,
// which re-runs a bundle's content-addressed policies to credit G0) both run it, so there is no second evaluator that can drift (native
// proof plan phase 6, brief 28bi).
//
// It depends on the Go standard library only (enforced by import_fence_test.go).
package policyeval
