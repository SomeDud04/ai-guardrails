# Local guard adapters (`nasi_lemak.guards`)

This module implements the two runtime guard adapters:

| Adapter | Role | Model candidate |
|---|---|---|
| `PromptGuard2` | attack screening of the serialized conversation | Meta Llama Prompt Guard 2 86M |
| `LlamaGuard3` | contextual output screening | Meta Llama Guard 3 1B |

The candidate names describe the **intended interfaces only**. They are not
license clearance, an approved artifact revision or a downloaded model, and no
pretrained checkpoint has been executed in this workspace.

`nasi_lemak.guards` imports **standard library only** at module load. `torch` and
`transformers` are imported lazily inside the loaders, so `nasi_lemak.guards`,
the gateway and the default test suite import and run without the optional ML
extra. When anything required is missing the adapter raises
`GuardError` — it never fabricates a `safe`/`allow` verdict.

## Local-only loading

The operator must pass an **existing local directory** containing a compatible
tokenizer, config and safetensors weights. There is no Hub-ID resolution, no
default download, no cache fallback and no run-time network access:

- `local_files_only=True`
- `trust_remote_code=False`
- `token=False`
- `use_safetensors=True` (model weights)
- `model.eval()` and an explicit CPU move (`model.to("cpu")`)

A repository ID such as `meta-llama/Llama-Guard-3-1B` is not an existing
directory, so it is rejected before any Transformers call; a URL is rejected
outright. Model approval, artifact revisions, license acceptance, serving
compatibility and hardware proof remain operator prerequisites.

## `PromptGuard2`

```python
guard = PromptGuard2("<LOCAL_DIR>", threshold=0.5)
guard.count_tokens(serialized)        # -> int
guard.scan_attack(serialized)         # -> {"decision": "allow"|"block"}
```

- `count_tokens` and `scan_attack` use the **same tokenizer** with
  `add_special_tokens=True` and `truncation=False`, so the gateway's token
  budget and the classifier window are directly comparable. There is no
  whitespace estimator.
- The complete serialized conversation is tokenized without truncation. Inputs
  over `PROMPT_GUARD_MAX_TOKENS` (512, special tokens included) are rejected as
  `block` **before** any forward pass.
- `model.config.id2label` must be a binary `{0, 1}` mapping whose
  case-normalized labels are exactly `BENIGN` and `MALICIOUS`. `LABEL_0`/`LABEL_1`
  semantics are never guessed; anything else fails closed.
- The MALICIOUS softmax probability must be finite. It is compared against an
  explicitly **uncalibrated** threshold (default `0.5`); the threshold must be a
  finite number in `[0, 1]`.
- Malformed logits, wrong score counts, non-finite values, non-integer token ids
  and model/tokenizer failures all raise `GuardError`.

## `LlamaGuard3`

```python
guard = LlamaGuard3("<LOCAL_DIR>", context_limit=2048)
guard.scan_response(messages, output)  # -> {"safe": bool}
```

- Every accepted message and role is serialized into one user message; the
  buffered model output is appended as the assistant turn. The model's own
  `tokenizer.apply_chat_template` is then applied with `tokenize=True` and
  `add_generation_prompt=True` (the model-card form) and without truncation, so
  no turn or `system` field is silently dropped.
- The template's exact token IDs, special tokens included, are counted against
  `min(context_limit, model.config.max_position_embeddings) - 32`; 32 tokens are
  reserved for the verdict **inside** the effective total. `context_limit` must
  be at least 33 as well as no larger than the model window, otherwise
  construction fails closed. A missing or invalid local context window also
  fails closed.
- Accepted EOS ids are derived from `model.generation_config.eos_token_id` when
  supplied (an int or a non-empty list of ids, so multi-EOS models keep their
  full termination set), then from the model config, then from the tokenizer.
  A supplied but malformed EOS configuration (`bool`, negative, empty list,
  non-integer member, duplicates) fails closed rather than falling back to a
  guessed token.
- Generation is deterministic: `max_new_tokens=32`, `do_sample=False`, with the
  derived accepted EOS configuration passed to `generate` (and a validated
  tokenizer pad id or the first accepted EOS as pad). Only the newly generated
  IDs are sliced (the prompt prefix is verified) and decoded with
  `skip_special_tokens=True`.
- Generated output must end in one of the accepted EOS ids. A missing EOS, an
  empty/truncated sequence, an early EOS followed by more tokens, or a sequence
  longer than the verdict window fails closed.
- Only the exact stripped verdict `safe` releases. `unsafe` (optionally followed
  by `S1`..`S13` category codes) blocks. All other text is an error — there is
  no substring matching and no allow-all fixture.

Both adapters are reusable, hold no per-request prompts or responses in
attributes and emit no logs; model calls are serialized with a per-adapter lock
for thread safety. `scan_response` keeps context stateless per call.

## Test injection seam

Every constructor also accepts keyword-only `tokenizer`, `model` and `backend`
(torch-like) objects. This seam exists **only** so deterministic tests can
exercise token boundaries, slicing, parsing and fail-closed behaviour without
installing the ML extra. Those objects are inference doubles: they are not
evidence of real guard efficacy, and no deployment may be approved on them.
`tests/test_guards.py` uses doubles exclusively.

## Error semantics

`GuardError` always carries a fixed, generic message. Raw prompt text, model
output, file paths and token values are never included in an error or a log.
When optional dependencies, model files, config, labels or inference are
unavailable, the adapter fails closed rather than returning a verdict.

## Validation limits

- Real pretrained inference has **not** been run here: `torch`/`transformers`
  are not installed in the workspace virtualenv and no model was downloaded.
  The tensor method chain (`detach()` → `cpu()` → `tolist()`), EOS selection and
  generation slicing are exercised only by tensor-like inference doubles.
- The exact `guards` pins (`torch==2.14.1`, `transformers==5.20.1`) were checked
  to exist in the official PyPI metadata only; they were not installed, and
  their mutual compatibility was not tested.
- No detection-quality, false-positive/negative, latency or hardware claims are
  made. The 500 ms p95 latency target remains unmeasured.
- Both adapters are wired into `nasi_lemak/server.py:make_adapters_from_env`
  behind explicit `NASI_LEMAK_*` settings. They are not exercised with real
  weights here, and the default Docker image does not install the `guards` extra
  or mount model directories.

## Local Qwen3Guard-Gen transport

`nasi_lemak.qwen3_local.Qwen3GuardLocal` runs `Qwen3Guard-Gen-0.6B` in-process on
CPU for both guard slots. It is a **causal generative** guard, and both
transports parse its text with the single parser in `nasi_lemak.qwen3guard` (no
second taxonomy or parser exists). The parser is lane-aware because the
artifact defines two verdict shapes: the input slot uses the artifact's official
two-line `Safety`/`Categories` verdict (an emitted `Refusal` is parsed, an
absent one is accepted), while the output slot and the HTTP wrapper keep the
strict three-line `Safety`/`Categories`/`Refusal` product verdict. `Jailbreak`
is a valid category in the input lane only; the response lane rejects it as an
unknown label and fails closed. One adapter serves the tokenizer slot, the
input attack slot and the output slot; `scan_attack` compares the verdict with
the input threshold and `scan_response` with the output threshold.

Select it explicitly with `NASI_LEMAK_GUARD_BACKEND=qwen3guard-local`. The
backend name is never inferred from a URL, a model directory or the API
selector. Every setting is independent and is validated **before** any loader
runs; a failure produces no adapter and the app stays unready:

| Environment variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `NASI_LEMAK_QWEN3GUARD_MODEL_DIR` | yes | none | Existing local directory only; no Hub ID, URL or download |
| `NASI_LEMAK_QWEN3GUARD_INPUT_THRESHOLD` | no | `0.5` | Categorical severity floor; valid range `0.0..0.5` |
| `NASI_LEMAK_QWEN3GUARD_OUTPUT_THRESHOLD` | no | `0.5` | Independent; same range |
| `NASI_LEMAK_QWEN3GUARD_WORKERS` | no | from CPU count | `1..8`; `workers * threads <= cpu_count` |
| `NASI_LEMAK_QWEN3GUARD_THREADS` | no | from CPU count | `1..8`; explicit intra-op torch threads |
| `NASI_LEMAK_QWEN3GUARD_LONG_INPUT` | no | `8192` | Single-call payload budget; `512..32768` |

The defaults are derived by `nasi_lemak.guard_pool`: `workers =
clamp(cpu // 2, 1, 4)` and `threads = clamp(cpu // workers, 1, 2)`. On the
4-vCPU guard box that is **`(2, 2)`**: two concurrent guard inferences, two
torch intra-op threads each. An explicit pair is rejected if either value is
outside `1..8` or if `workers * threads` exceeds the CPU count; nothing is
silently clamped. The pool admits at most `workers` scans, runs each request at
most once, honours a per-request deadline/cancellation before a slot reaches
the model, and propagates every failure as `GuardError` (never an allow).

### Local-only loading and structural validation

Loading uses the same discipline as the Meta adapters: an existing local
directory only, `local_files_only=True`, `trust_remote_code=False`,
`token=False`, safetensors weights only, device CPU explicitly, and an explicit
intra-op thread count. There is no Hub resolution, download, cache fallback or
retry. The CPU-only causal loader also loads the weights explicitly as
`float32`: the checkpoint is stored as bf16 and CPU bf16 matrix multiplication is
emulated (~330x slower than fp32 in a measured same-shape matmul), so an
implicit checkpoint dtype made every local scan miss the chat deadline. Llama
Guard 3 shares that CPU-only causal path and is therefore loaded as `float32`
too; the Meta sequence-classification loader is unchanged.

`trust_remote_code=False` is not by itself sufficient. The proven D12 failure
is that `transformers` may still map an unexpected artifact onto a built-in
class and silently initialise a **random** model, including a classifier. The
transport therefore fails closed at two independent points:

1. **Before loading**, by filename and artifact layout: reject
   `modeling_qwen3_guard.py` or `configuration_qwen3.py`, reject any
   `auto_map`, require a readable `config.json` declaring a `qwen3` model type
   and an explicit causal-LM architecture (missing or malformed declarations
   fail closed), and require at least one local `.safetensors` weight file.
   `Qwen3Guard-Stream` is excluded by design because it needs the rejected
   remote-code modules.
2. **After loading**, on the actual object: require a callable `generate`,
   require a valid causal architecture declaration, reject an actual classifier
   class or head, and require a positive context window plus a valid EOS
   configuration. For a checkpoint loaded from disk the runtime class must
   additionally be the supported Qwen3 causal class, so a
   sequence-classification object cannot pass merely by copying a causal
   declaration into its config. A generic `id2label` map (`LABEL_0`,
   `LABEL_1`, ...) is ordinary `PretrainedConfig` metadata and is **not**
   treated as proof of a classifier; nor is its presence used to accept one.
   Any structural surprise is a `GuardError`, never a default allow.

### One-call long input

Long input is screened in **one call**. There is no window split and no
truncation, because the 432-unit fixed framing is paid on every call and
splitting multiplies the dominant fixed cost. The budget is a payload budget;
the complete framed prompt is checked separately against the model window:

```
default: 8192 payload + 432 framing + 128 verdict reserve = 8752
         inside the 32768-position window
maximum: 32768 payload; the framing and 128-token reserve cannot also fit,
         so the very longest inputs are unscreenable
```

An input above the configured payload budget fails closed as `INPUT_LIMIT`. At
the `32768` ceiling a payload whose framed prompt would exceed
`32768 - 128 = 32640` positions fails closed the same way. It is never
truncated and never silently passed.

### Categorical verdict and threshold

The verdict is categorical (`Safety: Safe|Controversial|Unsafe` plus validated
categories and refusal), not a calibrated probability. A threshold is a
**severity floor** over `Safe=0.0`, `Controversial=0.5`, `Unsafe=1.0`, and the
decision is `severity >= threshold`. `0.5` is the maximum accepted value: above
it a `Controversial` verdict would stop blocking, which would relax the
contract rather than tighten it. A value above `0.5` is invalid configuration,
not a laxer knob.

### Honest limits

No Qwen3Guard checkpoint has been executed in this workspace or in the test
suite: there is no weight load, tokenizer execution, generation or network
access in these tests. All transport, pool, long-input and wiring tests use
explicit inference doubles. The benchmark measurement (latency, memory,
throughput) is a separate operator activity on the VM, and nothing here is
detection-quality, false-positive/negative or multilingual-coverage evidence.
Stream is not supported under this loader discipline; it would require remote
code, which the product forbids.

## References

- Meta Prompt Guard 2 86M model card:
  <https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M> (512-token
  window; binary `BENIGN`/`MALICIOUS`; `AutoTokenizer` +
  `AutoModelForSequenceClassification`)
- Meta Llama Guard 3 1B model card:
  <https://huggingface.co/meta-llama/Llama-Guard-3-1B> (causal LM `safe`/`unsafe`
  output; `tokenizer.apply_chat_template`)
- Transformers `from_pretrained` model loading:
  <https://huggingface.co/docs/transformers/main/en/main_classes/model>
