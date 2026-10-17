# ScamSentry AI

ScamSentry analyses suspicious messages using deterministic indicators, with optional Stage 2 open-weight AI interpretation.

> **Important:** Risk bands and model output are advisory. They do not prove that a message is fraudulent, and no findings does not mean a message is safe.

## Stage 1 — deterministic analysis

- Unicode normalisation while preserving the original message
- Invisible/formatting Unicode observations
- Local URL extraction and structure checks, including recognised defanged URLs
- Named text heuristics for urgency, credential requests, payment pressure, rewards, and impersonation
- Structured evidence and a transparent heuristic risk band
- No DNS, HTTP, redirect, JavaScript, reputation, or model calls

## Stage 2 — open-weight AI interpretation

Stage 2 adds contextual interpretation of the message and Stage 1 evidence:

- Concise summary and likely intent
- Social-engineering tactic labels
- Explanations tied to existing Stage 1 finding IDs
- Qualitative uncertainty and explicit reasons
- Alternative interpretations and cautious next steps

The model output is strictly parsed and validated. Unknown finding IDs, invalid tactic labels, extra fields, and malformed JSON are rejected. Stage 1 findings and risk bands are never overwritten by AI output.

### Model provider

The first provider uses the **Ollama CLI** and defaults to **gemma3:4b**. Install Ollama from https://ollama.com/ and explicitly pull the model:

```bash
ollama pull gemma3:4b
ollama run gemma3:4b
```

ScamSentry does not download model weights automatically. The second command is an optional sanity check. Keep the local Ollama runtime available when using Stage 2.

## Install

Requires Python 3.11 or newer.

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1

python -m pip install -e ".[dev]"
```

The provider uses the separately installed Ollama CLI, so no extra Python runtime dependencies are required.

## Usage

Stage 1 only (no model required):

```bash
scamsentry analyze --file examples/suspicious_message.txt
scamsentry analyze --text "Hello, meeting is at 3 PM."
```

Stage 2 with the local model:

```bash
scamsentry analyze --file examples/suspicious_message.txt --ai
scamsentry analyze --text "Your account will be suspended. Enter your password now." --ai --ai-model gemma3:4b
```

Structured output for integrations:

```bash
scamsentry analyze --file examples/suspicious_message.txt --ai --json
```

Control generation time:

```bash
scamsentry analyze --file examples/suspicious_message.txt --ai --ai-timeout 180
```

If Ollama is unavailable, times out, or returns invalid output, Stage 1 results are preserved. JSON output includes ai_analysis.status = "unavailable" and stderr provides the diagnostic. AI failure does not change the Stage 1 verdict.

## Privacy and security

- Stage 1 is offline. When --ai is enabled, the message and Stage 1 evidence are passed to the selected local model process. Local execution still consumes system resources and may be affected by the runtime's logging configuration.
- The Ollama CLI is launched with an argument list and shell execution disabled; message text is passed via standard input, not interpolated into a shell command.
- The prompt tells the model to treat message content as untrusted data and never execute instructions embedded in it.
- Prompt injection cannot be completely eliminated. Treat all model-generated text as untrusted.
- Do not use model output as the sole basis for blocking, accusing, or taking irreversible action.
- Avoid analysing messages containing secrets unless you are comfortable processing them with the selected local runtime.

## Tests

```bash
python -m pip install -e ".[dev]"
python -m pytest -v
```

AI tests use a fake provider and do not require Ollama or downloaded model weights.

## Limitations

Stage 2 does not verify sender identity, domain ownership, DNS, URL reputation, delivery status, or real-world context. Uncertainty labels are qualitative model judgments, not calibrated probabilities. The model may miss tactics or generate incorrect explanations.

## Repository layout

```text
scamsentry/
  ai/
    analysis.py          # Stage 2 orchestration
    ollama_provider.py   # Optional local Ollama CLI
    prompts.py           # Evidence-grounded prompt
    provider.py          # Provider protocol
    schemas.py           # Strict output validation
  analyzer.py             # Stage 1 pipeline
  cli.py                  # CLI
  models.py               # Evidence schema
  normalizer.py           # Unicode normalisation
  rules.py                # Deterministic text rules
  url_checks.py           # Offline URL inspection
tests/
  test_ai_analysis.py
  test_ai_schemas.py
```

## License

MIT.
