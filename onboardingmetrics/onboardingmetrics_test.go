// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package onboardingmetrics

import (
	"strings"
	"testing"
	"time"
)

func validEvent() Event {
	return Event{
		Version:   EventVersion,
		Time:      "2026-06-08T00:00:00Z",
		Source:    SourceCLI,
		SessionID: "s_abc",
		Event:     EventDemoCompleted,
		Mode:      ModeLocal,
		Result:    ResultSuccess,
	}
}

func TestMetricsEventValidate(t *testing.T) {
	ve := validEvent()
	if err := ve.Validate(); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
	bad := []func(*Event){
		func(e *Event) { e.Version = "2" },
		func(e *Event) { e.Source = "evil" },
		func(e *Event) { e.Event = "" },
		func(e *Event) { e.SessionID = "" },
		func(e *Event) { e.Time = "not-a-time" },
		func(e *Event) { e.Result = "maybe" },
		func(e *Event) { e.Mode = "testnet" },
		func(e *Event) { e.DurationMs = -1 },
	}
	for i, mut := range bad {
		e := validEvent()
		mut(&e)
		if err := e.Validate(); err == nil {
			t.Errorf("bad event #%d should have been rejected", i)
		}
	}
}

func TestMetricsRedaction(t *testing.T) {
	e := validEvent()
	e.Persona = "acc://alice.acme/book/1 was here"
	e.ErrorCode = "ref deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	red := Redact(e)
	if !red.Redacted {
		t.Error("Redact must set Redacted=true")
	}
	if strings.Contains(red.Persona, "acc://") {
		t.Errorf("account URL not redacted: %q", red.Persona)
	}
	if strings.Contains(red.ErrorCode, "deadbeef") {
		t.Errorf("long hash not redacted: %q", red.ErrorCode)
	}
}

func TestMetricsRedactionDetectsSensitive(t *testing.T) {
	if !IsSensitive("private_key=0x" + strings.Repeat("a", 64)) {
		t.Error("private key marker must be sensitive")
	}
	if !IsSensitive(strings.Repeat("ab", 32)) {
		t.Error("64-hex run must be sensitive")
	}
	if IsSensitive("L0_ENDPOINT_UNREACHABLE") {
		t.Error("a stable error code must not be flagged sensitive")
	}
	// SensitiveField rejects an event carrying an account URL or key.
	e := validEvent()
	e.Persona = "acc://secret.acme"
	if _, ok := SensitiveField(&e); !ok {
		t.Error("an account URL in a field must be flagged for rejection")
	}
}

func TestMetricsLocalStore(t *testing.T) {
	dir := t.TempDir()
	s := NewLocalStore(dir)

	if got, _ := s.Read(); len(got) != 0 {
		t.Fatalf("fresh store should be empty, got %d", len(got))
	}
	for i := 0; i < 3; i++ {
		e := validEvent()
		if err := s.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 events, got %d", len(got))
	}
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Read(); len(got) != 0 {
		t.Fatalf("after clear should be empty, got %d", len(got))
	}
}

func TestMetricsRecorderRedactsAndHashesSession(t *testing.T) {
	s := NewLocalStore(t.TempDir())
	r := NewRecorder(s, "raw-session-123")
	if r.SessionID() == "raw-session-123" || !strings.HasPrefix(r.SessionID(), "s_") {
		t.Fatalf("session id must be hashed, got %q", r.SessionID())
	}

	e := Event{Event: EventDemoCompleted, Mode: ModeLocal, Result: ResultSuccess, Persona: "acc://alice.acme"}
	if err := r.Record(e); err != nil {
		t.Fatalf("record: %v", err)
	}
	got, _ := s.Read()
	if len(got) != 1 {
		t.Fatalf("expected 1 stored event, got %d", len(got))
	}
	stored := got[0]
	if stored.SessionID != r.SessionID() {
		t.Errorf("stored session id %q != recorder %q", stored.SessionID, r.SessionID())
	}
	if !stored.Redacted {
		t.Error("stored event must be marked redacted")
	}
	if strings.Contains(stored.Persona, "acc://") {
		t.Errorf("stored event leaked an account URL: %q", stored.Persona)
	}
	if stored.Version != EventVersion || stored.Time == "" {
		t.Error("recorder must fill version + time")
	}
}

func TestMetricsOptInOut(t *testing.T) {
	s := NewLocalStore(t.TempDir())
	r := NewRecorder(s, "sess")

	// Default: enabled (local-only).
	if !r.Enabled() {
		t.Fatal("recording should be enabled by default")
	}
	// Opt out → records are dropped.
	if err := r.OptOut(); err != nil {
		t.Fatal(err)
	}
	if r.Enabled() {
		t.Fatal("opt-out should disable recording")
	}
	if err := r.Record(validEvent()); err != nil {
		t.Fatalf("record while opted out should be a no-op, not error: %v", err)
	}
	if got, _ := s.Read(); len(got) != 0 {
		t.Fatalf("opted-out recorder must store nothing, got %d", len(got))
	}
	// Opt back in → records again.
	if err := r.OptIn(); err != nil {
		t.Fatal(err)
	}
	if err := r.Record(validEvent()); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Read(); len(got) != 1 {
		t.Fatalf("opted-in recorder must store, got %d", len(got))
	}
}

func TestMetricsSummary(t *testing.T) {
	base := time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)
	at := func(d time.Duration) string { return base.Add(d).Format(time.RFC3339) }
	events := []Event{
		{Version: "1", Source: SourceCLI, SessionID: "s", Event: EventCommandStarted, Time: at(0)},
		{Version: "1", Source: SourceCLI, SessionID: "s", Event: EventDemoStarted, Mode: ModeLocal, Time: at(2 * time.Second), Persona: "dapp"},
		{Version: "1", Source: SourceCLI, SessionID: "s", Event: EventCommandSucceeded, Result: ResultSuccess, Time: at(5 * time.Second)},
		{Version: "1", Source: SourceCLI, SessionID: "s", Event: EventDemoCompleted, Result: ResultSuccess, Mode: ModeLocal, Time: at(60 * time.Second)},
		{Version: "1", Source: SourceCLI, SessionID: "s", Event: EventProofExported, Time: at(70 * time.Second)},
		{Version: "1", Source: SourceCLI, SessionID: "s", Event: EventProofVerified, Result: ResultSuccess, Time: at(134 * time.Second)},
		{Version: "1", Source: SourceCLI, SessionID: "s", Event: EventProofVerified, Result: ResultFailure, ErrorCode: "PROOF_MALFORMED", Time: at(140 * time.Second)},
	}
	s := Summarize(events)
	if !s.FirstDemoSuccess {
		t.Error("first demo success should be true")
	}
	if s.Persona != "dapp" {
		t.Errorf("persona = %q, want dapp", s.Persona)
	}
	if s.TimeToVerifiedMs == nil || *s.TimeToVerifiedMs != 134000 {
		t.Errorf("time to verified = %v, want 134000ms", s.TimeToVerifiedMs)
	}
	if s.TimeToProofMs == nil || *s.TimeToProofMs != 70000 {
		t.Errorf("time to proof = %v, want 70000ms", s.TimeToProofMs)
	}
	if s.ProofVerificationFailureRate != 0.5 {
		t.Errorf("proof verification failure rate = %v, want 0.5", s.ProofVerificationFailureRate)
	}
	if s.ExampleCompletionRate != 1.0 {
		t.Errorf("example completion rate = %v, want 1.0", s.ExampleCompletionRate)
	}
	if s.MostRecentFailureCode != "PROOF_MALFORMED" {
		t.Errorf("most recent failure = %q", s.MostRecentFailureCode)
	}
}

func TestMetricsSummaryEmpty(t *testing.T) {
	s := Summarize(nil)
	if s.SuggestedNextStep != "infrix demo start --mode local" {
		t.Errorf("empty summary should suggest the demo, got %q", s.SuggestedNextStep)
	}
}

// TestMetricsPrivacy pins the privacy guarantees: a key is never stored, an
// account URL is redacted by default, and there is no payload field to leak a
// proof bundle into.
func TestMetricsPrivacy(t *testing.T) {
	s := NewLocalStore(t.TempDir())
	r := NewRecorder(s, "sess")
	r.RecordQuiet(Event{
		Event:   EventProofVerified,
		Result:  ResultFailure,
		Persona: "acc://alice.acme private_key=0x" + strings.Repeat("ab", 32),
	})
	got, _ := s.Read()
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	blob := got[0].Persona
	if strings.Contains(blob, "acc://") {
		t.Errorf("account URL leaked: %q", blob)
	}
	if strings.Contains(strings.ToLower(blob), strings.Repeat("ab", 32)) {
		t.Errorf("key material leaked: %q", blob)
	}
}
