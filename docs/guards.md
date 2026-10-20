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
