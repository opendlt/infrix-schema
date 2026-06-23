// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package onboardingmetrics

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Recorder records onboarding events. It validates and redacts every event
// before writing, and writes nothing when the user has opted out. The store is
// resolved per-operation so the telemetry directory honors the current
// environment (tests set INFRIX_TELEMETRY_DIR per case).
type Recorder struct {
	storeFn   func() *LocalStore
	sessionID string // already hashed
	now       func() time.Time
}

// NewRecorder builds a recorder writing to a fixed store, hashing rawSession.
func NewRecorder(store *LocalStore, rawSession string) *Recorder {
	return &Recorder{
		storeFn:   func() *LocalStore { return store },
		sessionID: HashSessionID(rawSession),
		now:       time.Now,
	}
}

var (
	processSessionOnce sync.Once
	processSessionID   string
)

func processSession() string {
	processSessionOnce.Do(func() {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			processSessionID = HashSessionID("infrix-fallback-session")
			return
		}
		processSessionID = HashSessionID(hex.EncodeToString(b))
	})
	return processSessionID
}

// Default returns a recorder writing to the resolved telemetry directory with a
// per-process hashed session id. The directory is re-resolved on each operation
// so environment overrides take effect.
func Default() *Recorder {
	return &Recorder{
		storeFn: func() *LocalStore {
			dir, err := DefaultDir()
			if err != nil {
				// Last-resort: a temp dir, so recording degrades rather than panics.
				dir = "infrix-telemetry"
			}
			return NewLocalStore(dir)
		},
		sessionID: processSession(),
		now:       time.Now,
	}
}

// SessionID returns the recorder's hashed session id.
func (r *Recorder) SessionID() string { return r.sessionID }

// Enabled reports whether local recording is on (opt-out turns it off).
func (r *Recorder) Enabled() bool { return r.storeFn().LoadConfig().Enabled }

// Record fills defaults, validates, redacts, and appends the event — unless the
// user has opted out, in which case it is dropped silently. Recording never
// transmits anything off the machine.
func (r *Recorder) Record(e Event) error {
	if e.Version == "" {
		e.Version = EventVersion
	}
	if e.Source == "" {
		e.Source = SourceCLI
	}
	if e.Time == "" {
		e.Time = r.now().UTC().Format(time.RFC3339)
	}
	if e.SessionID == "" {
		e.SessionID = r.sessionID
	}
	if err := e.Validate(); err != nil {
		return err
	}
	red := Redact(e)
	store := r.storeFn()
	if !store.LoadConfig().Enabled {
		return nil
	}
	return store.Append(red)
}

// RecordQuiet records best-effort, swallowing errors — for hot CLI paths that
// must never fail a user command because telemetry hiccuped.
func (r *Recorder) RecordQuiet(e Event) {
	_ = r.Record(e)
}

// OptIn enables local recording.
func (r *Recorder) OptIn() error { return r.storeFn().SaveConfig(Config{Enabled: true}) }

// OptOut disables local recording.
func (r *Recorder) OptOut() error { return r.storeFn().SaveConfig(Config{Enabled: false}) }
