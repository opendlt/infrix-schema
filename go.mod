// infrix-schema: the stdlib-only Tier-0 contract/verification kernel extracted
// from the Infrix monorepo (docs/extraction-plan). It carries the intent
// goal/type vocabulary, the evidence-bundle / portable-package wire formats +
// offline verifiers, and the proof-receipt schema. It depends on nothing but
// the Go standard library (enforced by per-package import fences) so it can be
// consumed as an independent, versioned module.
module github.com/AccumulateNetwork/infrix-schema

go 1.25.7
