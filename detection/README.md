# detection/

Auto-populated detection bundles. Each subdirectory is a single hunt's output.

## Bundle layout (contract)

```
detection/<slug>-<hunt-id-8>/
├── REPORT.md              # markdown narrative for human reviewers
├── sigma/
│   └── behavior.yml       # Sigma rule — base for SIEM rule deployment
└── findings/
    └── hunt.json          # structured metadata for tooling
```

This layout is written by `agent-svc/src/lib/delivery.ts` in threat-hunt-mesh.

### REPORT.md

The full Report Writer markdown — 11 structured sections including executive
summary, hypothesis, queries executed, evidence, alternative explanations, and
recommended actions. Audience: SOC analysts and detection engineers.

### sigma/behavior.yml

A Sigma rule (YAML, `status: experimental` on first ship). Compiled from the
hunt's tradecraft detail by `buildSigmaRule()`. As of D32 step 1 this is still
a placeholder selection (`EventID: 1`); D32 step 3 replaces it with a real
compilation from `story.initial_query_strategy`.

### findings/hunt.json

Machine-readable hunt metadata:

```json
{
  "hunt_id": "uuid",
  "hypothesis": "...",
  "queries_executed": [...],
  "results_summary": "...",
  "pivots": [...],
  "affected_assets": [...],
  "finding_class": "CONFIRMED_TTP_PRESENT | SUSPICIOUS | ...",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "confidence": 0.0
}
```

## How to deploy a detection from here

1. Review the open PR (or the merged bundle).
2. Copy `sigma/behavior.yml` into your SIEM's rule ingestion pipeline.
3. Cross-reference `findings/hunt.json` for tuning context.
4. The `REPORT.md` is the operational runbook for the SOC analyst who fires on
   the rule.
