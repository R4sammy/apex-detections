# apex-detections

Detection rule repository for the **threat-hunt-mesh** pipeline.

This repository is **auto-populated** by [threat-hunt-mesh](https://github.com/R4sammy/threat-hunt-mesh).
Each pull request lands a complete detection bundle produced by a hunt cycle that has:

1. Surfaced positive technical signal during the Elastic-stack query phase.
2. Survived Hunt Lead `pre_finalize: ESCALATE` at the strategic gate.
3. Been reviewed by the Senior Security Reviewer agent (Claude Opus 4.7) which assigned a
   `finding_class`, `severity`, `confidence`, and `detection_disposition`.
4. Received `detection_disposition.decision = 'ship'` from the Senior Security Reviewer.

## What lands here

Every detection PR contains a single bundle directory under `detection/`:

```
detection/<slug>-<hunt-id-8>/
├── REPORT.md              # full hunt narrative produced by the Report Writer agent
├── sigma/
│   └── behavior.yml       # Sigma detection rule compiled from the hunt's tradecraft
└── findings/
    └── hunt.json          # structured hunt metadata (queries, pivots, senior security disposition)
```

See `detection/README.md` for the bundle layout contract.

## Branch + PR conventions

- Base branch: `main`
- PR head branch pattern: `mesh/<slug>-<hunt-id-8>`
- PR title pattern: `[<severity>] <hypothesis>`
- PR body: hunt ID, finding_class, severity, confidence, executive summary, source report URL

## Auto-merge policy

threat-hunt-mesh auto-merges (`squash`) when **all** of:

- `finding_class == CONFIRMED_TTP_PRESENT`
- `severity != CRITICAL`
- `detection_disposition.decision == ship`

All other PRs (CRITICAL severity, SUSPICIOUS findings, CONFIRMED_INCIDENT, etc.)
are left **open for human review** before merging.

## Manual contributions

This repo is primarily machine-written. Manual detection rule contributions are
allowed but should follow the same `detection/<slug>/{REPORT.md, sigma/*.yml, findings/*.json}`
layout so downstream tooling stays uniform.

## License

Internal — not for redistribution.
