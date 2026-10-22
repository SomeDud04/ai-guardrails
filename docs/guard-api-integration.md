# Guard API integration status (22 October 2026)

This note covers the **optional** API guard backend in
`nasi_lemak/guard_api.py` and its explicit server selection. It is verified only
with synthetic loopback HTTP fixtures. No guard endpoint, credential or
pretrained model was contacted or run in this workspace, so this is not evidence
of model quality, latency or availability.

## Selected roles

| Role | Selected model | Current state |
|---|---|---|
| Input / attack screening | `meta-llama/Llama-Prompt-Guard-2-86M` | API adapter and gateway-owned `/classify` contract v1 implemented and fixture-tested; live endpoint pending |
| Output screening | `Qwen/Qwen3Guard-Gen-4B` | API adapter runtime-wired for `NASI_LEMAK_GUARD_BACKEND=api`; live endpoint pending |

Official references:

- <https://huggingface.co/Qwen/Qwen3Guard-Gen-4B> — OpenAI-compatible serving,
  full user + assistant context for output screening, and the
  `Safety` / `Categories` / `Refusal` verdict fields.
- <https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M> — binary
  benign/malicious classifier with a 512-token window.

## Input classifier API contract v1

`NASI_LEMAK_INPUT_GUARD_CONTRACT` must be exactly
`nasi-lemak-input-classifier-v1` for the API backend. This is a gateway-owned
contract implemented by the gateway's input adapter; it is **not** a claim that
a stock Prompt Guard endpoint exposes this shape.

Request: `POST <NASI_LEMAK_INPUT_GUARD_URL>/classify`, JSON body with exactly:

```json
{"model": "<configured served model>", "input": "<complete serialized input>",
 "truncation": false, "max_input_tokens": 512}
```

Response: HTTP 200, JSON object with exactly these four fields:

```json
{"model": "<same configured served model>", "malicious_probability": 0.05,
 "input_tokens": 12, "truncated": false}
```

The adapter requires an exact key set (extra, missing or unknown fields fail
closed), the exact configured model, a finite non-boolean
`malicious_probability` in `[0, 1]`, a strict integer `input_tokens` in
`[1, 512]`, and `truncated` exactly `false`. Duplicate keys and non-finite JSON
numbers are rejected by the strict transport. A probability at or above the
explicit threshold blocks. Any HTTP error, timeout, redirect, invalid UTF-8,
oversize response, invalid JSON or contract mismatch raises a generic
`GuardError` with no retry and no endpoint/key detail. `count_tokens` returns
`conservative_byte_budget`, a UTF-8 byte bound for the gateway budget; it is
**not** a model tokenizer count and the remote contract enforces the 512-token
window itself.

## API backend settings

Default remains `NASI_LEMAK_GUARD_BACKEND=local`. Select the API backend only
with `NASI_LEMAK_GUARD_BACKEND=api` under `NASI_LEMAK_MODE=guarded`; unknown or
partial settings leave the app not ready and never fall back to local or test
adapters. All settings are validated before any client is constructed, and no
inference request is made during startup or readiness.

| Setting | Required | Notes |
|---|---|---|
| `NASI_LEMAK_INPUT_GUARD_URL` / `_MODEL` / `_AUTH` | yes | Base URL, exact served model, `bearer` or `none` |
| `NASI_LEMAK_INPUT_GUARD_API_KEY` or `_API_KEY_FILE` | bearer only | Exactly one; unreadable file is an error, no inline fallback |
| `NASI_LEMAK_INPUT_GUARD_THRESHOLD` | yes | Finite inclusive `[0, 1]` |
| `NASI_LEMAK_INPUT_GUARD_CONTRACT` | yes | Must be `nasi-lemak-input-classifier-v1` |
| `NASI_LEMAK_OUTPUT_GUARD_URL` / `_MODEL` / `_AUTH` | yes | Qwen3Guard chat-completions endpoint, exact model, auth mode |
| `NASI_LEMAK_OUTPUT_GUARD_API_KEY` or `_API_KEY_FILE` | bearer only | Exactly one; same file rules |
| `<PREFIX>_TIMEOUT`, `_CA_FILE`, `_MAX_RESPONSE_BYTES`, `_ALLOW_INSECURE_HTTP` | no | Same validated bounds and explicit HTTP opt-in as generation |

Guard keys are distinct from the generation/chat key and there is no credential
fallback. Local guard artifact directories and ML dependencies are not read or
imported in API mode.

## Data flow through the gateway

The input classifier receives the **raw** serialized conversation before the
existing PII masking step. The generation request then receives the PII-masked
conversation. The output guard receives that same masked conversation plus the
complete **buffered raw** generated output; PII masking of released output
happens only after the output verdict, so the guard endpoint can see sensitive
generated text. Select endpoints whose data handling accepts that flow.

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

API mode is selected only by `NASI_LEMAK_GUARD_BACKEND=api` under guarded mode;
the default local backend and the acknowledged test mode are unchanged. Backend,
contract, threshold and both dedicated configs are validated before any client
loader runs, and construction or readiness makes no inference HTTP call. The
composition reuses `RealGatewayAdapters`: the same `InputGuardApiAdapter` is the
tokenizer and attack guard, and `Qwen3GuardOutputAdapter` screens the output.

The API backend and contract are verified **only** against synthetic loopback
fixtures in `tests/test_guard_api_modes.py`. Live
endpoint behaviour, Prompt Guard quality, latency, availability and data-flow
approval remain pending. Do not claim live API quality or availability from this
slice.

Local versus API: the default local backend still needs local Prompt Guard and
Llama Guard artifacts. The API backend imports no local ML stack and instead
needs operator-supplied endpoints, served model IDs and credentials; neither
backend has live model-quality evidence here. The installer flow is documented
in [install-ubuntu.md](install-ubuntu.md) and the overlay is
[../compose.api.yaml](../compose.api.yaml). The selected deployment plan uses internal guard APIs under the
operator's control; public or third-party hosted alternatives require an
explicitly accepted data flow before real content is sent, and the free/hosted
options below are not an approved choice.

The local backend still requires PromptGuard2 and LlamaGuard3 artifacts plus a
valid generation configuration. Those local artifacts are not a
target-deployment dependency for the API backend, which imports no ML stack.

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
