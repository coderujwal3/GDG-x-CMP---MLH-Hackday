# ScamSentry AI

ScamSentry analyzes untrusted message text in three separate stages. Stage 1 deterministically extracts indicators, inspects embedded URLs **without contacting them**, and returns structured evidence. Optional Stage 2 uses a local open-weight model to interpret context and intent. Stage 3 validates and fuses those outputs deterministically into a separate risk band and defensive recommendations. A finding or model interpretation is **not** proof that a message is a scam.

Stage 1 is independent of every LLM provider and remains authoritative for findings and its original heuristic risk band. Stage 2 is opt-in and does not change Stage 1 findings. Stage 3 is deterministic and treats Stage 2 as context only; it does not require a cloud API or Python runtime dependency.

This is a **prototype**, not a substitute for security verification, fraud investigation, or incident response.

## Requirements & Supported Platforms

- **Python**: 3.11, 3.12, 3.13 (primary development target), and 3.14
- **Supported Operating Systems**:
  - Kali Linux and other Debian/Ubuntu-based Linux distributions
  - Windows 10/11 (PowerShell & Command Prompt)
  - macOS (Apple Silicon & Intel)
- **Runtime Dependencies**: Zero (Python standard library only)
- **Development & Testing Dependencies**: `pytest>=8.0`

## Installation & Setup

### Kali Linux & Linux Distributions
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install --no-build-isolation -e .
```

### Windows 10/11 (PowerShell)
```powershell
py -3.13 -m venv .venv
# If PowerShell execution policy blocks activation:
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install --no-build-isolation -e .
```

### macOS (Terminal / zsh)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install --no-build-isolation -e .
```

### Portable Execution (Without Package Installation)
You can run ScamSentry directly from any directory:
```bash
python -m scamsentry.cli analyze --text "Your account will be blocked. Verify now."
```

## CLI Usage

The command-line interface accepts exactly one input source (`--text` or `--file`):

```bash
# Direct command line invocation (after installation)
scamsentry analyze --text "Your account will be blocked. Verify now."
scamsentry analyze --file examples/suspicious_message.txt
scamsentry analyze --file examples/suspicious_message.txt --json

# Module invocation (cross-platform standard)
python -m scamsentry.cli --help
python -m scamsentry.cli analyze --help
python -m scamsentry.cli analyze --file examples/suspicious_message.txt
python -m scamsentry.cli analyze --file examples/suspicious_message.txt --json
```

Human-readable output omits the original message by default for privacy (pass `--include-message` to display it). JSON mode outputs machine-readable data to `stdout`, while status and errors go to `stderr`. Non-zero exit codes are returned for invalid input or file errors without exposing Python tracebacks.

Stage 2 uses an already-installed Ollama model and never downloads model weights:

```bash
# Install Ollama separately, then explicitly install the model you want:
ollama pull gemma3:4b

# Stage 1 plus local model interpretation (default model, 120-second timeout):
scamsentry analyze --file examples/suspicious_message.txt --ai

# Stage 1 plus deterministic Stage 3 decision, without a model:
scamsentry analyze --file examples/suspicious_message.txt --decision --json

# Select a different installed model and timeout:
scamsentry analyze --text "Your account is suspended." --ai \
  --ai-model gemma3:4b --ai-timeout 180 --json
```

If Ollama or the selected model is unavailable, Stage 1 is still returned and `ai_analysis.status` is `unavailable` in JSON. See the [CLI guide](docs/cli.md) for platform-specific instructions and the AI output contract.

Stage 3 runs with `--decision` or automatically alongside `--ai`. It adds a
separate `decision` object without changing Stage 1 or Stage 2 outputs. Review
the [versioned risk policy](docs/risk_policy.md) for fusion rules and
recommendation behavior.

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

Bands are a transparent heuristic triage policy, **not** a calibrated probability, and **never** conclusive proof of fraud.

| Band | Meaning |
|------|---------|
| `LOW_CONCERN` | No implemented check fired. **Not** proven safe. |
| `REVIEW` | At least one finding present, but insufficient independent vectors for high concern. Correlated indicators (such as brand impersonation derived solely from urgency) and multiple findings within the same category remain in REVIEW. |
| `HIGH_CONCERN` | At least two genuinely independent categories each have a MEDIUM or HIGH finding, and at least one HIGH finding exists (e.g. Urgency + Credential request, or Urgency + Suspicious URL). |
| `INCONCLUSIVE` | Analysis failed or is too incomplete (not used for a normal complete Stage 1 run). |

Repeated matches of the same rule and correlated cues do not inflate the band. Invalid input is an error, not a risk band. Missing Stage 2 model output is not a safety signal.

## Privacy and network

- Analysis performs **no DNS, HTTP, redirects, JavaScript, metadata, or reputation lookups**.
- `urllib.parse` and `ipaddress` are used locally. `urllib.request` is not used.
- Do not log full messages by default. Human CLI truncates evidence spans; JSON may contain the full original message.
- With `--ai`, the message and selected Stage 1 context are sent to the local Ollama CLI through stdin; inference and any runtime logging are governed by the local Ollama installation.

Offline URL inspection **cannot** establish whether a remote site is currently malicious.

## Documentation

- [Architecture and data flow](docs/architecture.md)
- [Installation and CLI usage](docs/cli.md)
- [Analysis methodology](docs/methodology.md)
- [Stage 3 risk policy](docs/risk_policy.md)
- [Limitations and safe use](docs/limitations.md)

## Testing & Cross-Platform Verification

### Unix Shell (Kali Linux / Ubuntu / macOS)
```bash
pytest -v
# or
python -m pytest -v
```

### Windows (PowerShell)
```powershell
python -m pytest -v
```

All test fixtures are synthetic. Tests never access the external network and do not require an AI model.

### Windows Verification Procedure
To verify this codebase on Windows 10/11 without modifying any source code:

1. Open PowerShell and navigate to the project directory:
   ```powershell
   cd \path\to\HackDay
   ```
2. Create and activate a Python 3.11+ virtual environment:
   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
3. Install dependencies and the package:
   ```powershell
   python -m pip install -r requirements.txt
   python -m pip install --no-build-isolation -e .
   ```
4. Run the full test suite:
   ```powershell
   python -m pytest -v
   ```
5. Test CLI functionality:
   ```powershell
   scamsentry analyze --text "Your account will be blocked. Verify now."
   scamsentry analyze --file examples\suspicious_message.txt
   scamsentry analyze --file examples\suspicious_message.txt --json
   ```

### Tested Platform Disclosure
- **Directly Executed Platform**: Linux (x86_64, Python 3.14.7).
- **CI coverage configured**: `.github/workflows/ci.yml` includes Ubuntu, Windows, and macOS with Python 3.11–3.13. No CI workflow result was available during this implementation, so those platforms are not reported as verified here.


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
