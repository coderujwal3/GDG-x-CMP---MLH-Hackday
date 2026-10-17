# Stage 3 Risk Policy

## Scope and version

This document defines deterministic Stage 3 risk policy version `1.0`.
Stage 3 validates and combines the existing Stage 1 result and optional
validated Stage 2 interpretation into a separate `decision` result. It does not
modify either input. Stage 1 remains the source of observable evidence; Stage 2
is advisory context only.

The decision schema version is `1.0`. The policy deliberately computes no
numeric score or probability. Risk bands are triage categories, not calibrated
estimates or verified reputation.

## Input validation

- Stage 1 must be an `AnalysisResult` with the supported schema version,
  supported status/risk enums, bounded message and finding counts, unique
  finding IDs, typed categories/severities/provenance, bounded text, and valid
  optional offsets.
- Unsupported or malformed Stage 1 data raises `DecisionInputError`; it is not
  silently assigned a risk band.
- Stage 2 must have the supported schema, status, model metadata and advisory
  disclaimer, and pass the existing strict Stage 2 parser. Finding references
  must refer to actual Stage 1 finding IDs.
- Invalid or unavailable Stage 2 is excluded. It does not invalidate a
  otherwise usable Stage 1 result.

## Final risk band

1. If Stage 1 status is not `complete`, return `INCONCLUSIVE`.
2. If Stage 1 is complete but has no findings, return `INCONCLUSIVE`. This
   conservative Stage 3 interpretation does not claim that Stage 1's original
   `LOW_CONCERN` result was wrong; it distinguishes "no implemented check
   matched" from evidence that a message is safe.
3. If findings exist, recompute the existing Stage 1 finding policy:
   - `HIGH_CONCERN` requires at least two distinct strong categories and at
     least one `HIGH` finding.
   - `REVIEW` applies when findings exist but that threshold is not met.
   - Repeated findings in one category do not increase the band.
   - Urgency and impersonation alone are correlated and do not count as
     independent categories.
4. If the supplied Stage 1 band differs from the recomputed result, retain the
   supplied band in `stage1_risk_band`, use the recomputed band as
   `final_risk_band`, and report the mismatch in `notes`.
5. Stage 2 never changes the final band. A conflicting model interpretation
   can be described in notes but cannot outweigh Stage 1 evidence. Model
   uncertainty also cannot make Stage 1 appear more certain: findings impose a
   minimum `moderate` uncertainty.

## Signals and traceability

Each Stage 1 finding becomes a separate `stage1` signal with its finding ID,
category, severity, and deterministic explanation. Stage 2 intent and tactics
may be included as `stage2` contextual signals without finding references.
Only Stage 1 finding IDs appear in `supporting_finding_ids` and in
recommendation evidence references. Stage 2 values are never relabeled as
verified facts.

The `policy_rules` list identifies the policy clauses used to reach the band.
`rationale` gives a compact human-readable description of those clauses.
Signals, policy rules, supporting IDs, and recommendation evidence references
are stable and deterministically ordered.

## Recommendations

Stage 3 emits fixed defensive advice derived only from Stage 1 categories:

| Finding category | Recommendation |
| --- | --- |
| Any finding or no findings | Pause and verify independently through a trusted contact method or website. |
| Credential | Do not enter passwords or one-time codes through message links. |
| Payment | Do not send money, gift cards, or cryptocurrency based on the message. |
| URL | Avoid opening the link; navigate to the official service independently. |
| Urgency or impersonation | Do not let pressure or claimed authority rush a decision. |
| Formatting | Treat unusual/invisible formatting as untrusted and compare in plain text. |

Each recommendation includes an action ID, action text, rationale, priority,
and supporting finding IDs. Priority is `immediate` for `HIGH_CONCERN`, `soon`
for `REVIEW`, and `routine` for `INCONCLUSIVE`. No model-suggested action is
executed or inserted into this fixed recommendation set.

## Uncertainty and failure handling

- Non-complete Stage 1: `unable_to_assess`.
- Complete Stage 1 with no findings: `high`.
- Complete Stage 1 with findings: at least `moderate`, elevated by validated
  Stage 2 uncertainty if it is higher.
- The `uncertainty_reasons` array records unperformed Stage 1 checks, the lack
  of external identity/reputation verification, and any validated Stage 2
  uncertainty reasons.
- Stage 2 unavailable or invalid does not change the band and is recorded in
  `ai_status` and `notes`.
- Stage 1 validation errors are explicit errors, not success-shaped fallback
  results.

Stage 3 is available via `--decision` and runs automatically when `--ai` is
requested. Omitting both flags preserves Stage 1 CLI output unchanged.
