# Guard API integration status (22 October 2026)

This note covers the **optional** Qwen3Guard output API adapter in
`nasi_lemak/guard_api.py`. It is a real adapter against the documented
OpenAI-compatible serving contract, verified only with loopback HTTP fixtures.
No Qwen3Guard endpoint, credential or pretrained model was contacted or run in
this workspace, so this is not evidence of model quality, latency or
availability.

## Selected roles

| Role | Selected model | Current state |
|---|---|---|
| Input / attack screening | `meta-llama/Llama-Prompt-Guard-2-86M` | Local adapter exists; hosted API contract not confirmed |
| Output screening | `Qwen/Qwen3Guard-Gen-4B` | Optional API adapter prepared and fixture-tested; not runtime-wired |

Official references:

- <https://huggingface.co/Qwen/Qwen3Guard-Gen-4B> — OpenAI-compatible serving,
  full user + assistant context for output screening, and the
  `Safety` / `Categories` / `Refusal` verdict fields.
- <https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M> — binary
  benign/malicious classifier with a 512-token window.

## Qwen verdict contract

The adapter requires the **complete** three-line verdict, in this order:

```text
Safety: Safe|Unsafe|Controversial
Categories: <comma-separated labels>|None
Refusal: Yes|No
```

Known categories are `Violent`, `Non-violent Illegal Acts`,
`Sexual Content or Sexual Acts`, `PII`, `Suicide & Self-Harm`,
`Unethical Acts`, `Politically Sensitive Topics` and `Copyright Violation`.

| Verdict | Adapter result |
|---|---|
| `Safety: Safe` and `Categories: None` | `{"safe": True}` |
| `Safety: Unsafe` with one or more known categories | `{"safe": False}` |
| `Safety: Controversial` with one or more known categories | `{"safe": False}` |
| Any other combination | `GuardError` (fail closed) |

`Refusal` is validated but never overrides the Safety line; an `Unsafe` verdict
with `Refusal: Yes` still blocks. Markdown fences, extra text, duplicate or
missing lines, reordered lines, unknown labels, and contradictions such as
`Safe` with categories or `Unsafe` with `None` are rejected. A transport error,
timeout, HTTP error or truncated/non-`stop` completion also becomes a generic
`GuardError`; the gateway then returns `503` without releasing buffered output.
The error text contains no endpoint, key, prompt or output.

## Data flow through the gateway

`Qwen3GuardOutputAdapter.scan_response(messages, output)` validates and copies
the supplied `messages` list and appends `output` as one assistant turn; it does
not mask, rewrite or truncate either argument. When composed through
`RealGatewayAdapters`, the gateway supplies the PII-masked generation messages
and the complete **buffered raw** generated output. PII masking of released
output happens only after output screening, so the guard endpoint can receive
sensitive generated text that has not yet been masked. Select an endpoint whose
data handling accepts that content.

The selected deployment plan uses internal guard APIs under the operator's
control. Public or third-party hosted alternatives require an explicitly
accepted data flow before real content is sent; the free/hosted options below
are not an approved choice.

## Programmatic construction

The adapter takes an explicitly configured existing `GenerationClient`. It has
no default URL, model, key, retry or fallback logic, and it is not created from the
application/chat credential. The example below is a placeholder only; the
served model ID or alias must be confirmed with one real response from the
operator's endpoint.

```python
from nasi_lemak.generation import GenerationClient, GenerationConfig
from nasi_lemak.guard_api import Qwen3GuardOutputAdapter

guard_config = GenerationConfig(
    url="https://guard.example.invalid/v1",   # placeholder, not a real host
    model="Qwen/Qwen3Guard-Gen-4B",           # or the confirmed served alias
    api_key="<dedicated-guard-placeholder-key>",
    timeout=10.0,
    max_response_bytes=8192,
)
guard = Qwen3GuardOutputAdapter(GenerationClient(guard_config))
result = guard.scan_response(messages, buffered_output)  # {"safe": ...}
```

Reusing `GenerationClient` keeps the existing bounded timeout, TLS
verification, no-redirect policy, response-size limit and explicit insecure-HTTP
opt-in. The adapter validates at most 16 context messages with exactly
`role`/`content`, accepted roles `system`, `user`, `assistant`, non-empty string
content, and a non-empty string output. It copies all accepted turns, appends
the output as an assistant turn without truncation, and rejects the request if
the UTF-8 JSON-encoded conversation exceeds 16 KiB. **That is a byte bound, not
a tokenizer count and not a model-window claim.** The verdict request asks for
at most 128 output tokens; the existing transport still rejects truncated,
non-`stop`, missing or refusal completions.

## Activation and remaining work

The adapter is **not** selected by the current server environment, installer or
Compose files, and constructing it alone cannot activate guarded mode. The
current legacy guarded startup still requires existing local PromptGuard2 and
LlamaGuard3 artifacts plus a valid generation configuration until API wiring
exists; those local artifacts are not a target-deployment dependency. The
selected target deployment uses internal guard APIs. The existing gateway already accepts
`output_guard.scan_response(messages, output)` through
`RealGatewayAdapters`, so runtime wiring is a small, explicit later step once
the endpoint is confirmed.

For the input classifier, the Prompt Guard model card describes a binary
classifier, not an OpenAI generative chat API. Before writing an input adapter,
confirm one actual response shape, the exact served model ID, truncation/window
handling at 512 tokens, score/threshold semantics, authentication and timeouts.
Until then, input API serving and environment wiring remain pending. The next
step is that input adapter plus explicit runtime configuration, followed by a
supervised live check; there is no silent test-mode fallback.

## Free/evaluation options (not selected models)

These links are dated 22 October 2026 and describe third-party free tiers or
hosted options, not an approved production choice. Account creation, API keys,
rate limits and data-egress terms apply. Do not send customer content to any
hosted service until the customer accepts that data flow; use synthetic inputs
only.

| Option | Dated source | Caveat |
|---|---|---|
| Groq free plan listing Prompt Guard 86M | <https://console.groq.com/docs/rate-limits> | Model availability/limits can change under account |
| OpenAI moderation | <https://developers.openai.com/api/docs/guides/moderation> | Different taxonomy; content leaves the boundary |
| Mistral moderation | <https://docs.mistral.ai/models/mistral-moderation-26-03> | Separate provider contract; not Prompt Guard/Qwen |
| Hugging Face Qwen3Guard weights | <https://huggingface.co/Qwen/Qwen3Guard-Gen-4B> | Weights availability is not a hosted API promise |

There is no confirmed free hosted Qwen3Guard endpoint. Free tiers require
accounts and keys, are rate-limited, and receive the submitted content.
