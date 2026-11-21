// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package intent

import (
	"encoding/json"
	"testing"
)

// The submitter-declared intent priority (core item 2c part 28w row 2): the closed vocabulary, empty meaning normal, refused by exact
// comparison otherwise, and carried on the wire as goal.priority.
func TestIntentPriorityValidatesTheClosedVocabularyAndEmptyMeansNormal(t *testing.T) {
	for _, p := range []IntentPriority{"", PriorityNormal, PriorityHigh, PriorityUrgent} {
		if err := p.Validate(); err != nil {
			t.Errorf("priority %q refused: %v", p, err)
		}
	}
	for _, p := range []IntentPriority{"URGENT", " urgent", "low", "critical", "normal "} {
		if err := p.Validate(); err == nil {
			t.Errorf("priority %q accepted", p)
		}
	}
	if IntentPriority("").Effective() != PriorityNormal || PriorityUrgent.Effective() != PriorityUrgent {
		t.Fatal("an undeclared priority is not priced as normal, or a declared one is not kept")
	}
	if len(ValidIntentPriorities) != 3 {
		t.Fatalf("the vocabulary holds %d priorities, want normal, high and urgent", len(ValidIntentPriorities))
	}
}

func TestIntentPriorityIsCarriedOnTheWireAsGoalPriority(t *testing.T) {
	raw, err := json.Marshal(IntentGoal{Type: GoalCustom, Priority: PriorityUrgent})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back["priority"] != "urgent" {
		t.Fatalf("the goal encodes as %s, want priority urgent", raw)
	}
	plain, _ := json.Marshal(IntentGoal{Type: GoalCustom})
	var bare map[string]any
	if err := json.Unmarshal(plain, &bare); err != nil {
		t.Fatal(err)
	}
	if _, present := bare["priority"]; present {
		t.Fatalf("an undeclared priority is encoded: %s", plain)
	}
}
