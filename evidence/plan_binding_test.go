// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package evidence

import "testing"

// TestThePlanHashBindsEverySubjectField (brief 28bu row 2): with evaluations the plan hash differs from the content hash, and changing any
// subject field, the policy, the scope, the type or the order of the evaluations changes it; with none it is the content hash.
func TestThePlanHashBindsEverySubjectField(t *testing.T) {
	content := [32]byte{1, 2, 3}
	if BindPlanHash(content, nil) != content {
		t.Fatal("a plan governed under no evaluation must keep its content hash")
	}
	amt := 10.0
	base := func() []PolicyEvaluation {
		a := amt
		return []PolicyEvaluation{
			{PolicyType: "escrow:release", ScopeKey: "global", Policy: PolicyRef{Hash: [32]byte{9}}, Subject: PolicySubject{Actor: "acc://a", Contract: "acc://c", Function: "release", BlockHeight: 7, Amount: &a}},
			{PolicyType: "system:authorization", ScopeKey: "global", Policy: PolicyRef{Hash: [32]byte{8}}, Subject: PolicySubject{Actor: "acc://a", BlockHeight: 7}},
		}
	}
	want := BindPlanHash(content, base())
	if want == content {
		t.Fatal("a plan governed under evaluations kept its bare content hash")
	}
	if BindPlanHash(content, base()) != want {
		t.Fatal("the binding is not deterministic")
	}
	other := 11.0
	for name, mut := range map[string]func(e []PolicyEvaluation) []PolicyEvaluation{
		"actor":     func(e []PolicyEvaluation) []PolicyEvaluation { e[0].Subject.Actor = "acc://b"; return e },
		"contract":  func(e []PolicyEvaluation) []PolicyEvaluation { e[0].Subject.Contract = "acc://d"; return e },
		"function":  func(e []PolicyEvaluation) []PolicyEvaluation { e[0].Subject.Function = "refund"; return e },
		"height":    func(e []PolicyEvaluation) []PolicyEvaluation { e[0].Subject.BlockHeight = 8; return e },
		"amount":    func(e []PolicyEvaluation) []PolicyEvaluation { e[0].Subject.Amount = &other; return e },
		"no amount": func(e []PolicyEvaluation) []PolicyEvaluation { e[0].Subject.Amount = nil; return e },
		"policy":    func(e []PolicyEvaluation) []PolicyEvaluation { e[0].Policy.Hash[0] ^= 1; return e },
		"scope":     func(e []PolicyEvaluation) []PolicyEvaluation { e[0].ScopeKey = "contract:acc://c"; return e },
		"type":      func(e []PolicyEvaluation) []PolicyEvaluation { e[0].PolicyType = "escrow:refund"; return e },
		"order":     func(e []PolicyEvaluation) []PolicyEvaluation { e[0], e[1] = e[1], e[0]; return e },
		"dropped":   func(e []PolicyEvaluation) []PolicyEvaluation { return e[:1] },
		"content":   func(e []PolicyEvaluation) []PolicyEvaluation { return e },
	} {
		c := content
		if name == "content" {
			c[0] ^= 1
		}
		if BindPlanHash(c, mut(base())) == want {
			t.Errorf("changing the %s left the plan hash the approvals signed unchanged", name)
		}
	}
}
