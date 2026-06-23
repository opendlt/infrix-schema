// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package onboardingmetrics

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// File + env names.
const (
	eventsFile = "local-events.jsonl"
	configFile = "config.json"

	// EnvTelemetryDir overrides the telemetry directory outright (used by
	// tests and power users).
	EnvTelemetryDir = "INFRIX_TELEMETRY_DIR"
	// EnvHome overrides the Infrix home (telemetry lives under <home>/telemetry).
	EnvHome = "INFRIX_HOME"
)

// DefaultDir resolves the telemetry directory: INFRIX_TELEMETRY_DIR, else
// <INFRIX_HOME>/telemetry, else ~/.infrix/telemetry.
func DefaultDir() (string, error) {
	if d := os.Getenv(EnvTelemetryDir); d != "" {
		return d, nil
	}
	if h := os.Getenv(EnvHome); h != "" {
		return filepath.Join(h, "telemetry"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("onboardingmetrics: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".infrix", "telemetry"), nil
}

// Config is the persisted privacy choice. Recording is LOCAL-ONLY and on by
// default; opt-out disables it. Nothing is ever transmitted off the machine.
type Config struct {
	Enabled bool `json:"enabled"`
}

// LocalStore is the append-only JSONL store under the telemetry dir.
type LocalStore struct {
	dir string
}

// NewLocalStore builds a store rooted at dir.
func NewLocalStore(dir string) *LocalStore { return &LocalStore{dir: dir} }

// Dir returns the store directory.
func (s *LocalStore) Dir() string { return s.dir }

// EventsPath is the JSONL file path.
func (s *LocalStore) EventsPath() string { return filepath.Join(s.dir, eventsFile) }

// ConfigPath is the config file path.
func (s *LocalStore) ConfigPath() string { return filepath.Join(s.dir, configFile) }

func (s *LocalStore) ensureDir() error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return fmt.Errorf("onboardingmetrics: create telemetry dir: %w", err)
	}
	return nil
}

// Append writes one event as a JSON line. The event must already be valid +
// redacted (Recorder guarantees this).
func (s *LocalStore) Append(e Event) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("onboardingmetrics: encode event: %w", err)
	}
	f, err := os.OpenFile(s.EventsPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("onboardingmetrics: open events file: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("onboardingmetrics: append event: %w", err)
	}
	return nil
}

// Read returns all recorded events in order. A missing file yields no events.
func (s *LocalStore) Read() ([]Event, error) {
	f, err := os.Open(s.EventsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("onboardingmetrics: open events file: %w", err)
	}
	defer f.Close()

	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Event
		if json.Unmarshal(line, &e) == nil {
			out = append(out, e)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("onboardingmetrics: read events: %w", err)
	}
	return out, nil
}

// Clear removes the events file (keeps the config / opt choice).
func (s *LocalStore) Clear() error {
	if err := os.Remove(s.EventsPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("onboardingmetrics: clear events: %w", err)
	}
	return nil
}

// LoadConfig reads the privacy choice. Absent config → enabled (local-only).
func (s *LocalStore) LoadConfig() Config {
	data, err := os.ReadFile(s.ConfigPath())
	if err != nil {
		return Config{Enabled: true}
	}
	var c Config
	if json.Unmarshal(data, &c) != nil {
		return Config{Enabled: true}
	}
	return c
}

// SaveConfig persists the privacy choice.
func (s *LocalStore) SaveConfig(c Config) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("onboardingmetrics: encode config: %w", err)
	}
	if err := os.WriteFile(s.ConfigPath(), data, 0o600); err != nil {
		return fmt.Errorf("onboardingmetrics: write config: %w", err)
	}
	return nil
}
