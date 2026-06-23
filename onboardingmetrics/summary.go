// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package onboardingmetrics

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// Summary is the computed onboarding picture for the local dashboard + the
// hosted funnel. Every rate has a clearly-defined denominator (see Summarize)
// so "is onboarding improving?" is answerable, not a matter of taste.
type Summary struct {
	TotalEvents int    `json:"totalEvents"`
	Persona     string `json:"persona,omitempty"`

	FirstDemoSuccess bool `json:"firstDemoSuccess"`

	// Time-to-X measured from the earliest recorded event. nil = not reached.
	TimeToFirstSuccessMs *int64 `json:"timeToFirstSuccessMs,omitempty"`
	TimeToProofMs        *int64 `json:"timeToProofMs,omitempty"`
	TimeToVerifiedMs     *int64 `json:"timeToVerifiedProofMs,omitempty"`
	TimeToFirstNexusMs   *int64 `json:"timeToFirstNexusMs,omitempty"`
	TimeToFirstCinemaMs  *int64 `json:"timeToFirstCinemaMs,omitempty"`

	MostRecentFailureCode string `json:"mostRecentFailureCode,omitempty"`
	SuggestedNextStep     string `json:"suggestedNextStep"`

	SetupFailureRate             float64 `json:"setupFailureRate"`
	MetaMaskRejectionRate        float64 `json:"metaMaskRejectionRate"`
	KermitFinalityTimeoutRate    float64 `json:"kermitFinalityTimeoutRate"`
	ProofVerificationFailureRate float64 `json:"proofVerificationFailureRate"`
	ExampleCompletionRate        float64 `json:"exampleCompletionRate"`
}

func rate(num, den int) float64 {
	if den <= 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func parseTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// Summarize computes the onboarding summary from an ordered event slice.
//
// Rates (denominator → 0 yields 0):
//   - setupFailureRate              = failed commands with a SETUP_* code / commands completed
//   - metaMaskRejectionRate         = METAMASK_USER_REJECTED / all METAMASK_* errors
//   - kermitFinalityTimeoutRate     = L0_FINALITY_TIMEOUT / kermit-mode events
//   - proofVerificationFailureRate  = failed proof.verified / all proof.verified
//   - exampleCompletionRate         = demo.completed / demo.started
func Summarize(events []Event) Summary {
	s := Summary{TotalEvents: len(events)}
	if len(events) == 0 {
		s.SuggestedNextStep = "infrix demo start --mode local"
		return s
	}

	t0, haveT0 := parseTime(events[0].Time)

	var (
		commandsCompleted int
		setupFailures     int
		mmErrors          int
		mmRejected        int
		kermitEvents      int
		kermitTimeouts    int
		proofVerifyTotal  int
		proofVerifyFail   int
		demoStarted       int
		demoCompleted     int
	)
	setFirst := func(dst **int64, t time.Time) {
		if *dst != nil || !haveT0 {
			return
		}
		ms := t.Sub(t0).Milliseconds()
		if ms < 0 {
			ms = 0
		}
		v := ms
		*dst = &v
	}

	for i := range events {
		e := events[i]
		when, ok := parseTime(e.Time)
		if !ok {
			when = t0
		}
		if e.Persona != "" {
			s.Persona = e.Persona // most recent persona wins
		}

		switch e.Event {
		case EventCommandSucceeded:
			commandsCompleted++
			setFirst(&s.TimeToFirstSuccessMs, when)
		case EventCommandFailed:
			commandsCompleted++
		case EventDemoStarted:
			demoStarted++
		case EventDemoCompleted:
			demoCompleted++
			if e.Result != ResultFailure {
				s.FirstDemoSuccess = true
			}
		case EventProofExported:
			setFirst(&s.TimeToProofMs, when)
		case EventProofVerified:
			proofVerifyTotal++
			if e.Result == ResultFailure {
				proofVerifyFail++
			} else {
				setFirst(&s.TimeToVerifiedMs, when)
			}
		case EventCinemaOpened:
			setFirst(&s.TimeToFirstCinemaMs, when)
		}

		if e.Source == SourceNexus {
			setFirst(&s.TimeToFirstNexusMs, when)
		}
		if e.Mode == ModeKermit {
			kermitEvents++
		}

		switch e.ErrorCode {
		case "":
			// no error
		default:
			if e.Result == ResultFailure {
				s.MostRecentFailureCode = e.ErrorCode // last failure wins
			}
			if strings.HasPrefix(e.ErrorCode, "SETUP_") && e.Result == ResultFailure {
				setupFailures++
			}
			if strings.HasPrefix(e.ErrorCode, "METAMASK_") {
				mmErrors++
				if e.ErrorCode == "METAMASK_USER_REJECTED" {
					mmRejected++
				}
			}
			if e.ErrorCode == "L0_FINALITY_TIMEOUT" {
				kermitTimeouts++
			}
		}
	}

	s.SetupFailureRate = rate(setupFailures, commandsCompleted)
	s.MetaMaskRejectionRate = rate(mmRejected, mmErrors)
	s.KermitFinalityTimeoutRate = rate(kermitTimeouts, kermitEvents)
	s.ProofVerificationFailureRate = rate(proofVerifyFail, proofVerifyTotal)
	s.ExampleCompletionRate = rate(demoCompleted, demoStarted)
	s.SuggestedNextStep = suggestNextStep(s)
	return s
}

func suggestNextStep(s Summary) string {
	persona := s.Persona
	if persona == "" {
		persona = "dapp"
	}
	if s.MostRecentFailureCode != "" {
		return "infrix doctor --persona " + persona
	}
	if !s.FirstDemoSuccess {
		return "infrix demo start --mode local"
	}
	if s.TimeToVerifiedMs == nil {
		return "infrix verify <bundle>.infrix.json --l0 kermit"
	}
	return "infrix learn --next"
}

func humanizeMs(ms *int64) string {
	if ms == nil {
		return "not yet"
	}
	d := time.Duration(*ms) * time.Millisecond
	if d < time.Second {
		return fmt.Sprintf("%dms", *ms)
	}
	m := int(d.Minutes())
	sec := int(d.Seconds()) % 60
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, sec)
	}
	return fmt.Sprintf("%ds", sec)
}

// Render writes the human onboarding dashboard (adoption-12).
func (s Summary) Render(w io.Writer) {
	fmt.Fprintln(w, "Onboarding summary")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "First demo success: %s\n", yesno(s.FirstDemoSuccess))
	fmt.Fprintf(w, "Time to proof: %s\n", humanizeMs(s.TimeToProofMs))
	fmt.Fprintf(w, "Time to verified proof: %s\n", humanizeMs(s.TimeToVerifiedMs))
	if s.MostRecentFailureCode != "" {
		fmt.Fprintf(w, "Most recent failure: %s\n", s.MostRecentFailureCode)
	} else {
		fmt.Fprintln(w, "Most recent failure: none")
	}
	fmt.Fprintf(w, "Proof verification failure rate: %.0f%%\n", s.ProofVerificationFailureRate*100)
	fmt.Fprintf(w, "Example completion rate: %.0f%%\n", s.ExampleCompletionRate*100)
	fmt.Fprintf(w, "Events recorded (local-only): %d\n", s.TotalEvents)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Suggested next step: %s\n", s.SuggestedNextStep)
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
