# infrix-schema

**The stdlib-only contract / verification kernel for [Infrix](https://github.com/opendlt).**

`infrix-schema` is the Tier-0 contract module extracted from the Infrix
monorepo. It defines the canonical, wire-stable shapes that everything else in
the Infrix ecosystem agrees on — the intent vocabulary, the evidence-bundle and
portable-package formats, the proof-receipt schema, the assurance ladder, and
the onboarding-metrics types. It is the single source of truth those contracts
are checked against.

It depends only on the **Go standard library** (a purity fence enforces this), so
it can be consumed as a tiny, stable, independently-versioned dependency by the
node, the verifier, the SDKs, and any third-party integrator — with no risk of
pulling in the runtime.

## Install

```sh
go get github.com/opendlt/infrix-schema@latest
```

```go
import (
    "github.com/opendlt/infrix-schema/intent"
    "github.com/opendlt/infrix-schema/evidence"
    "github.com/opendlt/infrix-schema/proofreceipt"
    "github.com/opendlt/infrix-schema/assurance"
    "github.com/opendlt/infrix-schema/onboardingmetrics"
)
```

## Packages

| Package | What it carries |
|---------|-----------------|
| `intent` | The goal/type vocabulary and intent wire shapes |
| `evidence` | The `EvidenceBundle` and `PortableEvidencePackage` wire formats + Merkle inclusion / anchor proof types |
| `proofreceipt` | The canonical proof-receipt schema, fail-closed `Validate`, and the text / HTML renderers |
| `assurance` | The proof-level (L0–L4) / governance-level (G0–G2) ladder and IU assurance classes |
| `onboardingmetrics` | Privacy-first, local-only onboarding telemetry types (hashed sessions, redaction) |

## Design

- **Stdlib-only.** No third-party dependencies; a fence test rejects any new
  import outside the standard library. This keeps the contract surface small and
  auditable.
- **Wire-stable.** These types are the bytes that cross process and trust
  boundaries; a portable evidence package serialized here is what an independent
  verifier re-reads with no trust in the producing node.
- **Fail-closed validation.** `proofreceipt.Validate` and the evidence checks
  reject structurally-invalid or over-claiming inputs rather than passing them
  through.

## License

MIT — see [LICENSE](LICENSE).
