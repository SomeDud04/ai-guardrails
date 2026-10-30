# RCA — Deployed lane returned 503 after the E8 rebuild

| Field | Value |
|---|---|
| Date | 29 Oct 2026 |
| Environment | `ai-guardrail-demo` (192.168.90.41, 4 vCPU), image `nasi-lemak-gateway:0.1.0-pilot` built from `805b807` |
| Severity | Pilot lane unusable for ordinary prompts (no data released; fail-closed held) |
| Status | Root cause confirmed; lane verified green with a short-answer prompt; permanent fix pending |
| Failing request | `req_73be06a809454d40bca3c3a483673d87` (audit seq 527 → 528) |
| First green request | `req_e8fa179093f94f0fb42a61152f371487` (200, 19.6 s, `finish_reason: stop`) |

## Summary

After rebuilding the VM with the E8 fix, `POST /v1/chat/completions` still returned
`503 UNAVAILABLE` ("Required safety control is unavailable"). The guards were not at
fault. The test prompt ("Explain GPU virtualization.") made the generation model
(`qwen3.8-27b`) write a long article that hit the gateway's default **1,024-token reply
limit**. The upstream returned `finish_reason: "length"`, and the gateway rejects any
non-`stop` completion as a failed generation (`nasi_lemak/generation.py`, `_extract_content`),
which surfaces as the same generic 503 as a guard failure.

This was **not** a context-window problem: the prompt was 18 tokens, and Qwen3Guard's
window is 32k tokens.

## Timeline (UTC)

| Time | Event |
|---|---|
| 15:13:53.217 | `request_started` (pending) |
| ≈15:13:59.7 | Input guard verdict `Safe` (≈6.5 s, measured separately) |
| ≈15:14:15.3 | Upstream stops at 1,024 tokens, `finish_reason=length` (≈16.2 s) |
| 15:14:15.313 | `request_failed` (failed, UNAVAILABLE) — total 22.1 s |

## Investigation

| Check | Result | Conclusion |
|---|---|---|
| Deployed commit | `805b807` built and running | E7/E8 fixes are live |
| `/health/ready` | ready, guards active, all counters 0 | Misleading — see contributing factor 2 |
| Audit delta | 22.1 s (< ≈30 s work deadline) | A stage raised an error; not a timeout |
| In-container guard probe | input `Safety: Safe\nCategories: None` in 6.5 s; response 3-line verdict in 9.8 s (short reply) / 31.0 s (≈1,000-token reply) | Both guard lanes work; prompt-template and parser fixes confirmed |
| Container env | backend `qwen3guard-local`, workers 1, threads 4, nproc 4 | As intended |
| Generation probe (max_tokens 1024) | `GenerationError … [generation_truncated]` after 16.2 s, both with and without the thinking override (`enable_thinking` already `False`) | Generation is the failing stage |
| Raw upstream probe | as-sent: `finish=length`, 1,024 completion tokens, 4,389 visible chars, 0 reasoning chars. With "Answer in 3 sentences.": `finish=stop`, 76 tokens, 1.3 s | Answer is genuinely too long; no hidden reasoning |
| End-to-end with the concise prompt | 200, 19.6 s | Full pipeline is healthy |

## Root cause

The default reply budget (1,024 tokens, `NASI_LEMAK_CHAT_DEFAULT_REPLY_TOKENS`) does not
fit what the generation model writes for open-ended prompts, and nothing asks the model
to be concise. When the model reaches the limit, the deliberate fail-closed rule
(never release a truncated completion) turns it into a 503.

## Contributing factors

1. **Same error for every failure.** Guard faults, generation truncation and upstream
   errors all return the identical generic 503, and the gateway does not log the
   internal reason. Diagnosis needed hand-written in-container probes.
2. **Readiness counters miss `/v1` requests.** `generation_truncated` and
   `generation_no_final_content` are only recorded through the workspace `ScanContext`
   (`workspace_http.py`). The OpenAI-compatible path passes none, so the counters stayed
   at 0 while the failure was exactly `generation_truncated`.
3. **The output guard is slow on long replies.** CPU float32 Qwen3Guard-Gen-0.6B on
   4 threads needs ≈31 s for a ≈1,000-token reply, and `scan_response` is not bounded by
   the request deadline. Raising the reply limit alone would therefore move the failure
   to the ≈30 s work deadline or the 60 s client deadline.
4. **Test prompt.** The rebuild acceptance check used an open-ended prompt; the earlier
   live proof (E8) used short replies, so the long-answer path had never been exercised.

## What worked as designed

- Fail-closed: nothing was released, every failure was audited as `request_failed`.
- E7/E8 fixes: chat-template delivery, lane-aware parsing and float32 loading all
  verified live in the container.

## Corrective actions

| # | Action | Type | Status |
|---|---|---|---|
| 1 | Add a gateway/policy-level brevity system instruction and lower the default reply limit to ≈384 tokens so typical answers finish with `stop` and the output scan stays ≈10–15 s | Fix (code + config) | Done (82015bc), verified on the VM |
| 2 | Record `generation_*` diagnostic codes for `/v1` and `/chat` requests too, not only workspace requests | Observability | Done (82015bc), verified on the VM |
| 3 | Log the internal failure stage and reason (server-side only, never in the response) for every `request_failed` | Observability | Done (82015bc), verified on the VM |
| 4 | Decide whether a truncated answer may be released after a full output scan (`finish_reason: "length"`), or stays a hard failure | Product decision | Open |
| 5 | Make the VM acceptance check use both a short-answer and a long-answer prompt, with expected outcomes | Process | Proposed |
| 6 | Benchmark output-scan latency against reply length (the pending `bench_guard_models.py` run) to set the reply budget from data | Evidence | Pending |

## Evidence scope

All measurements are from the single pilot VM on 29 Oct 2026, one run each. They are
local demo evidence, not production latency or accuracy figures.
