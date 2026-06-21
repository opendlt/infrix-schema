// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package proofreceiptschema

import (
	"fmt"
	"html"
	"strings"
)

// RenderText renders the friendly, expert-skippable CLI form. The wording is
// stable (the Go text-renderer test pins it) so downstream tooling can match
// on it.
func RenderText(r *Receipt) string {
	var b strings.Builder
	b.WriteString(statusHeadline(r.Status))
	b.WriteString("\n\n")

	fmt.Fprintf(&b, "Assurance: %s\n", orNone(r.Assurance.Label))
	fmt.Fprintf(&b, "Trusts Infrix node: %s\n", yesNo(r.NodeTrusted()))
	fmt.Fprintf(&b, "L0 anchor: %s\n", l0Line(r))
	fmt.Fprintf(&b, "Replay: %s\n", replayLine(r))
	fmt.Fprintf(&b, "Witness quorum: %s\n", witnessLine(r))

	if len(r.Warnings) > 0 {
		b.WriteString("\nWarnings:\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "  - %s\n", w)
		}
	}

	if ref := strings.TrimSpace(r.DetailsRef); ref != "" {
		b.WriteString("\nView details:\n")
		fmt.Fprintf(&b, "  infrix receipt inspect %s\n", ref)
	} else {
		b.WriteString("\nView details:\n")
		b.WriteString("  infrix receipt inspect <receipt.json>\n")
	}
	return b.String()
}

func statusHeadline(status string) string {
	switch status {
	case StatusVerified:
		return "VERIFIED"
	case StatusPartial:
		return "PARTIALLY VERIFIED"
	default:
		return "NOT VERIFIED"
	}
}

func l0Line(r *Receipt) string {
	if r.Assurance.L0Verified {
		net := strings.TrimSpace(r.Verification.Network)
		if net != "" {
			return "confirmed on " + net
		}
		return "confirmed"
	}
	return "not checked (offline)"
}

func replayLine(r *Receipt) string {
	if r.Assurance.ReplayVerified {
		return "reproduced"
	}
	return "not reproduced"
}

func witnessLine(r *Receipt) string {
	if r.Assurance.WitnessQuorumVerified {
		return "verified"
	}
	return "not required"
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(none)"
	}
	return s
}

// RenderHTML renders a compact, self-contained receipt card: the default view
// (status + assurance + badges) plus an expandable <details> with the full
// artifact + verification material. Raw hashes are inside the expansion only.
func RenderHTML(r *Receipt) string {
	esc := html.EscapeString
	var b strings.Builder
	cls := "receipt-" + r.Status
	b.WriteString(`<div class="proof-receipt ` + cls + `" data-status="` + esc(r.Status) + `">`)
	b.WriteString(`<div class="proof-receipt-status">` + esc(statusHeadline(r.Status)) + `</div>`)
	if s := strings.TrimSpace(r.Summary); s != "" {
		b.WriteString(`<div class="proof-receipt-summary">` + esc(s) + `</div>`)
	}
	b.WriteString(`<div class="proof-receipt-assurance">` + esc(orNone(r.Assurance.Label)) + `</div>`)

	b.WriteString(`<ul class="proof-receipt-badges">`)
	b.WriteString(badge("node trust", "no node trust required", !r.NodeTrusted()))
	b.WriteString(badge("L0", l0Line(r), r.Assurance.L0Verified))
	b.WriteString(badge("replay", replayLine(r), r.Assurance.ReplayVerified))
	b.WriteString(badge("witness", witnessLine(r), r.Assurance.WitnessQuorumVerified))
	b.WriteString(`</ul>`)

	if n := len(r.Warnings); n > 0 {
		fmt.Fprintf(&b, `<div class="proof-receipt-warnings">%d warning(s)</div>`, n)
	}

	// Expanded details — full hashes + verification material.
	b.WriteString(`<details class="proof-receipt-details"><summary>Details</summary>`)
	b.WriteString(`<dl class="proof-receipt-fields">`)
	field(&b, esc, "Subject", r.Subject.Type+" "+r.Subject.ID)
	field(&b, esc, "Proof level", r.Assurance.ProofLevel)
	field(&b, esc, "Governance level", r.Assurance.GovernanceLevel)
	field(&b, esc, "Intent", r.Artifacts.IntentID)
	field(&b, esc, "Plan", r.Artifacts.PlanID)
	field(&b, esc, "Outcome", r.Artifacts.OutcomeID)
	field(&b, esc, "Evidence", r.Artifacts.EvidenceID)
	field(&b, esc, "Anchor tx", r.Artifacts.AnchorTx)
	field(&b, esc, "Verifier", r.Verification.Verifier)
	field(&b, esc, "Command", r.Verification.Command)
	field(&b, esc, "Network", r.Verification.Network)
	field(&b, esc, "Verified at", r.Verification.VerifiedAt)
	for _, w := range r.Warnings {
		field(&b, esc, "Warning", w)
	}
	b.WriteString(`</dl></details></div>`)
	return b.String()
}

func badge(name, text string, on bool) string {
	state := "off"
	if on {
		state = "on"
	}
	return `<li class="proof-receipt-badge" data-badge="` + html.EscapeString(name) + `" data-on="` + state + `">` + html.EscapeString(text) + `</li>`
}

func field(b *strings.Builder, esc func(string) string, label, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	b.WriteString(`<dt>` + esc(label) + `</dt><dd>` + esc(value) + `</dd>`)
}
