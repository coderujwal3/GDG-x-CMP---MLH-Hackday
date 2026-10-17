# ScamSentry AI (Stage 1)

Deterministic, offline analysis of untrusted message text. The engine extracts indicators, inspects embedded URLs **without contacting them**, and returns structured evidence. It distinguishes what was observed from what was inferred. A finding is **not** proof that a message is a scam.

Stage 1 is independent of every LLM provider. Stage 2 can add a local open-weight model (for example Gemma 4) without changing the Stage 1 `Finding` / `AnalysisResult` interfaces (`source="deterministic"` today; `source="model"` later).

This is a **prototype**, not a substitute for security verification, fraud investigation, or incident response.

## Requirements

- Python 3.11 or newer
- Stage 1 runtime dependencies: none (stdlib only)
- Tests: `pytest`

## Install

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Without a package install you can still run:

```bash
PYTHONPATH=. python -m scamsentry.cli analyze --text "hello"
```

## CLI

Exactly one input source (`--text` or `--file`):

```bash
python -m scamsentry analyze --text "Your account will be suspended. Enter your password."
python -m scamsentry.cli analyze --file examples/suspicious_message.txt
python -m scamsentry.cli analyze --file examples/suspicious_message.txt --json
```

Human-readable output omits the original message by default (pass `--include-message` to include it). JSON output includes `original_message` so a later pipeline can quote evidence; treat JSON as sensitive.

- JSON goes to stdout; diagnostics go to stderr.
- Non-zero exit on invalid input, file errors, or unexpected failures.
- Ordinary users do not receive Python tracebacks.

Library API:

```python
from scamsentry import analyse_message

result = analyse_message(message)
print(result.risk_band, result.finding_count)
```

## Detection categories

| ID prefix | Category | What is looked for |
|-----------|----------|--------------------|
| A | Urgency / threats | Account blocking, short deadlines, loss of access |
| B | Credential / sensitive | Password, OTP / verification code, banking details |
| C | Payment / reward | Unexpected fees, immediate payment, prize / refund / reward |
| D | Impersonation | Org claim **combined** with pressure or a sensitive request (brand mention alone is not enough) |
| E | URL structure | IP hosts, userinfo, unusual ports, recognised defanged links, conservative misleading subdomains, risky schemes |
| F | Formatting | Invisible / formatting Unicode; original text is preserved |

Recognised defanging is limited to patterns such as `hxxp` / `hxxps`, `example[.]com`, and `hxxps[:]//`. The original URL text is kept; a separate normalised candidate is used for parsing.

## Risk bands

Bands are a transparent rule-based policy, **not** a calibrated probability and **not** verified reputation.

| Band | Meaning |
|------|---------|
| `LOW_CONCERN` | No implemented check fired. **Not** proven safe. |
| `REVIEW` | At least one finding, but the HIGH_CONCERN rule did not apply. |
| `HIGH_CONCERN` | At least two independent categories each have a MEDIUM or HIGH finding, and at least one HIGH finding exists. |
| `INCONCLUSIVE` | Analysis failed or is too incomplete (not used for a normal complete Stage 1 run). |

Repeated matches of the same rule do not inflate the band. Invalid input is an error, not a risk band. Missing Stage 2 model output is not a safety signal.

## Privacy and network

- Analysis performs **no DNS, HTTP, redirects, JavaScript, metadata, or reputation lookups**.
- `urllib.parse` and `ipaddress` are used locally. `urllib.request` is not used.
- Do not log full messages by default. Human CLI truncates evidence spans; JSON may contain the full original message.

Offline URL inspection **cannot** establish whether a remote site is currently malicious.

## Tests

```bash
pytest
```

All fixtures are synthetic. Tests do not use the network or an AI model.

## Example outputs

Human (abridged):

```
ScamSentry AI — Stage 1 deterministic analysis
Status: complete
Risk band: HIGH_CONCERN (rule-based policy, not a probability)
Findings: 10
Original message omitted (pass --include-message to show it; message text may be sensitive).
```

JSON is a single object with `schema_version`, `original_message`, `findings`, `finding_count`, `analysis_status`, `checks_performed`, `checks_incomplete`, `limitations`, and `risk_band`.

## Limitations and false-positive risks

- Phrase matching will miss paraphrases and will fire on some legitimate security or billing mail.
- URL shorteners, odd query strings, and “non-standard looking” hosts are **not** treated as malicious by appearance alone.
- Misleading-host detection is conservative: a known brand token as a **subdomain of an unrelated registrable domain** (for example `paypal.unrelated-example.test`). Typosquatting of the registrable domain itself is out of scope.
- Invisible Unicode is flagged; the analyser never silently treats rewritten text as trustworthy.
- Input is never executed, evaluated, or interpreted as code, shell, markup, or model instructions.
- Not bug-free; see the test suite for covered behaviour.

## License

MIT. Copyright (c) 2026 ScamSentry AI contributors.
