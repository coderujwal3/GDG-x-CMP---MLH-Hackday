# Installation and CLI Guide

## Requirements

- Python 3.11 or newer. The project currently has no required Python runtime
  packages.
- Stage 2 additionally requires a separately installed Ollama CLI and a local
  model already present in Ollama.
- Stage 3 is deterministic, offline, and has no additional dependencies.
- The default Stage 2 model is `gemma3:4b`; the default timeout is 120 seconds
  per Ollama CLI operation.
- ScamSentry never downloads model weights automatically.

## Install ScamSentry

From the repository root, create and activate a virtual environment, install
the test dependency and install ScamSentry in editable mode.

### Linux (bash)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install --no-build-isolation -e .
```

### macOS (Terminal / zsh)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install --no-build-isolation -e .
```

### Windows 10/11 (PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install --no-build-isolation -e .
```

If PowerShell blocks activation, use the appropriate execution-policy guidance
for your environment or invoke `.venv\Scripts\python.exe` directly. Activation
is not required to use the virtual environment's Python executable.

## Install Ollama and a model explicitly

Install Ollama using its official installation instructions for your operating
system, and ensure its local service is available. Then fetch the model
intentionally:

```text
ollama pull gemma3:4b
```

The pull command is a user action. ScamSentry only checks installed models with
`ollama list`; if the selected model is missing, it reports `model_not_installed`
and suggests an explicit pull command. ScamSentry does not start a cloud
inference service or send data to an API.

## Run Stage 1 only

Stage 1 stays the default and requires no AI installation:

```text
scamsentry analyze --text "Your account will be blocked. Verify now."
scamsentry analyze --file examples/suspicious_message.txt
scamsentry analyze --file examples/suspicious_message.txt --json
```

It can also be run from a source checkout:

```text
python -m scamsentry.cli analyze --file examples/suspicious_message.txt
```

## Run Stage 2

Pass `--ai` to request local interpretation:

```text
scamsentry analyze --file examples/suspicious_message.txt --ai
scamsentry analyze --text "Your account is suspended. Enter your password." --ai
scamsentry analyze --file examples/suspicious_message.txt --ai --json
```

Choose a different model already installed in Ollama and a timeout:

```text
scamsentry analyze --text "Review this notice." --ai --ai-model gemma3:4b --ai-timeout 180
```

`--ai-model` alone does not enable AI. `--ai-timeout` must be a finite positive
number of seconds. The timeout is applied to each Ollama CLI invocation (model
listing and generation).

## Run Stage 3

Use `--decision` to validate Stage 1 and produce a deterministic final risk
band with evidence-linked defensive recommendations, without starting a model:

```text
scamsentry analyze --file examples/suspicious_message.txt --decision
scamsentry analyze --file examples/suspicious_message.txt --decision --json
```

Stage 3 also runs automatically with `--ai`. Stage 2 is optional context only:
it cannot create or remove Stage 1 evidence or alter the Stage 3 risk band.
Stage 3 uses the Stage 1 finding-based risk policy, treats incomplete analyses
as inconclusive, and treats no findings as inconclusive rather than evidence of
safety. See [risk_policy.md](risk_policy.md) for policy version 1.0.

## Output and failures

- Without `--ai` or `--decision`, JSON output has the original Stage 1 schema.
- With `--ai`, JSON adds `ai_analysis` without changing any Stage 1 values.
  Successful output has `status: "complete"`; failures have
  `status: "unavailable"` and a stable error code.
- With `--decision`, JSON adds a separate `decision` object; `--ai` also
  includes this object automatically. Without either option, default output is
  unchanged.
- An invalid Stage 2 object is excluded and reported as `decision.ai_status:
  "invalid"`; an unavailable local model is reported as `"unavailable"`.
- Human output labels Stage 1 deterministic findings and Stage 2 AI
  interpretation separately from the Stage 3 decision and recommended actions.
- JSON stays on stdout. Warnings and diagnostics go to stderr.
- If optional AI fails, the CLI still returns the complete Stage 1 result and
  preserves its existing successful exit code. This is not an AI success
  signal: inspect `ai_analysis.status` or stderr.
- Existing CLI usage errors return code 2; invalid message or file input
  returns code 1. A successful Stage 1 run returns code 0.
- User-facing errors do not include prompts or raw child-process stderr.

Common failures:

| Error code | Meaning / action |
| --- | --- |
| `provider_unavailable` | Install Ollama and make `ollama` available on `PATH`; ensure the local service can respond. |
| `model_not_installed` | Run the displayed `ollama pull MODEL` explicitly, then retry. |
| `generation_timeout` | Increase `--ai-timeout` or select a smaller/quantized local model. |
| `model_execution_failed` | Check local Ollama installation/service; no message is automatically retried. |
| `invalid_json` / `invalid_schema` | The model response did not match the strict output contract; Stage 1 remains usable. |

## Privacy

Stage 1 does not perform DNS, HTTP, redirect, or reputation checks. When `--ai`
is used, ScamSentry sends the original message and selected Stage 1 context to
the local Ollama process via stdin. The local model/runtime may consume
substantial CPU, memory, and disk, and its own logging behavior is outside
ScamSentry's control. Avoid sending sensitive messages unless permitted by your
organization's policy. Neither message nor prompt is logged by ScamSentry by
default.

Human output omits the original message unless `--include-message` is passed.
JSON includes the full Stage 1 original message as before.

## Tests

From the project root:

```text
python -m pytest -v
```

The suite mocks Ollama and does not need model weights, network access, or a
GPU.
