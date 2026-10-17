# Analysis Methodology

## Evidence and interpretation

ScamSentry separates three different concerns:

- **Stage 1:** Which implemented patterns and URL structures are observable in
  the submitted text?
- **Stage 2:** What intent or social-engineering tactic might those observations
  suggest in context?
- **Stage 3:** What deterministic triage band and defensive next steps follow
  from validated Stage 1 evidence, with Stage 2 retained as optional context?

Stage 1 findings retain identifiers such as `F001`, a rule ID, category,
severity, evidence text, and a deterministic explanation. These are
observations or named heuristics, not proof of sender identity or fraud.
Stage 2 may interpret only the Stage 1 finding IDs supplied in its prompt.
Its explanations are separately stored in `ai_analysis.finding_explanations`;
they never become Stage 1 findings.

The Stage 1 risk band remains its existing transparent heuristic. Stage 2
cannot change it, and the band is not a probability or externally verified
reputation.

Stage 3 validates the typed Stage 1 result and any supplied Stage 2 envelope,
normalizes their traceable signals into a separate result, and computes a
versioned final risk band. It never edits either input. Stage 2 interpretations
are not evidence: they cannot independently raise or lower risk, and invalid or
unavailable Stage 2 output is excluded while Stage 1 remains usable.

## Deterministic Stage 1

Stage 1 validates UTF-8 input size, creates a separate normalized matching form,
preserves the original message, finds rule-based urgency, credential, payment,
impersonation, and formatting indicators, and inspects URL syntax locally.
URL checks do not contact destinations. The existing independent-category risk
policy avoids treating repeated or correlated indicators as independent proof.

No fired rule means only that no implemented check matched. It does not prove
that a message is harmless.

## Contextual Stage 2

Stage 2 is an optional, local model interpretation. Its prompt includes the
original message and selected Stage 1 evidence using JSON serialization. The
prompt distinguishes trusted analysis instructions from untrusted message
content and tells the model to treat embedded commands as text to analyze.
This reduces but does not eliminate prompt-injection risk.

The model is instructed to keep observed content and inferred intent separate,
avoid claims of external verification or certainty, give plausible benign
alternatives, and recommend proportionate defensive actions. A model response
is not trusted until its JSON structure, value types, taxonomy labels, lengths,
and finding references pass validation.

## Controlled classifications

The machine-readable likely-intent labels are:

`obtain_credentials`, `obtain_payment`, `induce_link_visit`,
`collect_personal_information`, `create_fear_or_urgency`,
`impersonate_an_organisation`, `unsolicited_marketing`,
`benign_or_informational`, and `unclear`.

The tactic labels are:

`authority_impersonation`, `urgency_or_time_pressure`,
`credential_harvesting`, `payment_or_fee_pressure`, `prize_or_reward_lure`,
`fear_or_threat`, `social_proof`, `romance_or_trust_exploitation`,
`delivery_or_account_lure`, `malicious_link_lure`, `other`, and
`none_observed`. `none_observed` cannot be combined with another tactic.
Mention of money, passwords, delivery, or urgency alone does not require a
suspicious label.

Qualitative uncertainty is `low`, `moderate`, `high`, or
`unable_to_assess`. It is not a confidence score. High and unable-to-assess
outputs must include at least one concrete uncertainty reason.

## Context, alternatives, and safe actions

The model receives incomplete Stage 1 checks and can account for them when
describing limitations. Typical reasons for uncertainty include missing sender
context, inability to verify an organization, unavailable URL reputation,
ambiguous wording, multiple plausible explanations, short text, and incomplete
checks.

Alternative explanations should be plausible and specific, such as an ordinary
account notice or parcel update. Recommended actions should be safe and
proportionate, such as independently opening the official application or
contacting the organization through a known channel. Advice should not require
clicking a supplied link, sharing credentials, or making an irreversible
decision based solely on the model's output.

If Stage 1 has no findings, Stage 2 can still describe likely context. It must
not treat the empty finding list as evidence of safety. Finding explanations
may be partial; the schema does not assert that every finding was explained.

## Evaluation guidance

The repository's tests use synthetic fixtures and verify deterministic
behavior and schema boundaries; they are not an accuracy benchmark. To conduct
a future evaluation:

1. Build a consented, privacy-reviewed dataset with message-level labels and
   an explicit annotation guide.
2. Include benign security/billing/delivery notifications, ambiguous messages,
   varied languages, and multiple social-engineering patterns.
3. Keep a held-out set separate from prompt and rule development.
4. Measure Stage 1 detection and Stage 2 classifications separately; report
   false positives, false negatives, per-class precision/recall, and abstention
   or unable-to-assess rates.
5. Record exact model, version, quantization, runtime, and prompt/schema
   versions; repeat runs where model output may vary.
6. Review explanations and action recommendations for unsupported claims,
   unsafe advice, and missed uncertainty.

No accuracy, latency, or calibration claim is made by this project. Calibration
and empirical comparisons are future research, not implemented capabilities.

## Deterministic Stage 3

Stage 3 risk policy version `1.0` recomputes the existing Stage 1 risk policy
from validated findings rather than trusting a potentially inconsistent
supplied band. It retains the Stage 1 band and reports any mismatch. Partial,
failed, or otherwise non-complete analyses are `INCONCLUSIVE`; a complete
analysis with no findings is also `INCONCLUSIVE` because no implemented check
firing does not establish safety. With findings, Stage 3 follows the existing
independent-category and high-severity threshold. Urgency and impersonation
indicators remain correlated and cannot be counted as independent categories.

Every Stage 1 signal keeps its finding ID, category, severity, and deterministic
explanation. Stage 2 intent/tactic signals are explicitly labeled as model
context and have no finding reference. Recommendations are fixed defensive
actions selected from Stage 1 categories, with supporting finding IDs, a
priority, and a reason. No numerical score or probability is calculated.
Qualitative uncertainty is not a confidence score; it is at least moderate
when findings exist, high when there are no findings or Stage 2 is unavailable
or invalid, and unable-to-assess for incomplete Stage 1.

See [risk_policy.md](risk_policy.md) for the exact versioned rules and output
contract.
