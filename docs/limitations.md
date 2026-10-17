# Limitations and Safe Use

ScamSentry is a prototype for defensive triage. It is not a security verdict,
fraud investigation, incident-response service, or substitute for independent
verification and security testing.

## Deterministic analysis limitations

- Phrase rules can miss paraphrases, unfamiliar languages, and new lures, and
  can flag legitimate billing, security, delivery, or account notices.
- The existing URL parser evaluates local structure only. It does not establish
  ownership, current reputation, page contents, redirects, or whether a site is
  malicious.
- ScamSentry performs no DNS, HTTP, redirect, JavaScript, metadata, or remote
  reputation lookup.
- Incomplete or unimplemented checks may matter for a particular message.
- Absence of findings is not proof that a message is safe.
- A high heuristic band is not a probability and does not confirm fraud.

## Deterministic decision limitations

- Stage 3 applies explicit rules to Stage 1 categories; it is not an empirically
  validated or calibrated decision model.
- `INCONCLUSIVE` for a complete analysis with no findings is deliberately
  conservative and does not mean that the message is malicious.
- Stage 2 is advisory only. Its validated schema does not establish factual
  accuracy, and it cannot add evidence or change the final risk band.
- Recommendations are fixed defensive guidance mapped from Stage 1 categories.
  They may not cover every context and do not replace human review or incident
  response.

## Model limitations

- Local language models can hallucinate, misunderstand context, omit findings,
  overstate intent, or provide unsafe advice. Strict schema validation checks
  structure and references, not semantic truth.
- Prompt injection remains a residual risk. Untrusted message text is
  JSON-serialized and separated from instructions, but a model may still be
  influenced by malicious content.
- A message may omit the sender, delivery channel, prior conversation, or
  organizational context. The model cannot verify identity based on a claim in
  the message.
- The uncertainty labels are qualitative and uncalibrated. They are not
  percentages, probabilities, or comparable confidence measurements.
- Model output and resource needs vary by model, model version, quantization,
  runtime, hardware, and settings. No universal latency or memory guarantee is
  made.
- The model may provide a plausible benign explanation for a malicious message
  or infer suspicious intent from a legitimate one.

## Privacy and local runtime

Stage 1 works without a model, Ollama, network, or model weights. With `--ai`,
the original message and selected Stage 1 context are passed to a local Ollama
CLI process through stdin. ScamSentry does not call a cloud API or log the
prompt by default. However, the local Ollama installation may maintain its own
logs, consume substantial resources, or be configured in ways ScamSentry
cannot inspect.

Do not send confidential, personal, or regulated content to a model unless
authorized by the applicable policy. Review local runtime installation,
permissions, storage, logs, and model provenance. Use the Stage 1-only command
when local model processing is not appropriate.

## Safe-use recommendations

- Verify account, payment, delivery, or security notices by independently
  opening a known official application or using a previously verified contact
  method.
- Do not use links or phone numbers solely because the message provides them.
- Never share passwords, one-time codes, or recovery keys in response to a
  message.
- Do not make payments, disclose sensitive data, or take irreversible action
  based only on an AI classification or recommended action.
- Treat message content, links, model output, and findings as evidence requiring
  human judgment.
- Report suspected fraud through established organizational or service
  channels and follow incident-response procedures where applicable.

These limitations do not replace security review, tests on supported
environments, or a risk assessment for a particular deployment.
