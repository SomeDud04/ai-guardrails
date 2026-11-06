# Response latency review (6 November 2026)

Review of where a guarded reply's time goes on the pilot VM, and options to shorten
it. Measurements come from the VM; nothing below has been changed yet.

## Measurements

From the two API key history exports of the 6 November live runs (298 requests,
one at a time, synthetic prompts):

| Outcome | Requests | Median | Range |
|---|---|---|---|
| Allowed (full reply) | 158 | 16.7 s | 13.0 to 26.6 s (p95 23.9 s) |
| Blocked by the input guard | 80 | 6.0 s | |
| Blocked by a deny phrase | 33 | 5.5 s | |

For allowed requests, total time fits **14.2 s + 29 ms per reply token** (r = 0.93).
Generation runs at about 58 tokens per second (17 ms per token), so the other
~12 ms per token is the output guard reading the reply.

Monitor's stage averages tell the same story: input guard 5.7 s, generation 2.7 s,
output guard 11.2 s.

**Monitor's "Guard tokens per second" is not the guard's speed.** It is prompt tokens
divided by the whole scan time, and a scan both reads the prompt and writes a verdict of
up to 128 tokens one at a time. Verdict tokens are not counted, and the figure averages
the last 20 input and output scans together. It is neither a read speed nor a write
speed, and it is not comparable with the model's tokens per second shown beside it,
which counts tokens written. A cleaner estimate of the read speed comes from the
reply-length slope above: about 12 ms per extra reply token, so roughly 80 tokens per
second. The verdict-writing time is not measured anywhere yet.

## Why the output guard is the slowest

The guard model (Qwen3Guard-Gen-0.6B) runs on CPU in float32. Each scan reads a whole
prompt before writing a short verdict, so its time follows the prompt length:

- **Input scan:** the model's own chat template with its safety policy text, plus the
  conversation. A one-line prompt still costs about 5.5 s, so most of it is fixed
  template text, not the user's words.
- **Output scan:** the same template, plus a 432-unit product framing
  (`GUARD_FRAMING`), plus the whole conversation, plus the full reply, and a longer
  three-line verdict. That is roughly twice the input scan's prompt.
- The VM has 4 cores and already runs the guard with `NASI_LEMAK_QWEN3GUARD_THREADS=4`
  and `NASI_LEMAK_QWEN3GUARD_WORKERS=1` (checked 6 November). One scan already uses
  the whole CPU, so there is no thread setting left to tune.

## Options

| # | Change | Expected effect | Effort and risk |
|---|---|---|---|
| 1 | Measure each scan properly: prompt tokens, verdict tokens, time to read and time to write, per lane, and show those on Monitor instead of the blended figure | Tells us whether reading or writing dominates, which decides between options 2 and 4 | Instrumentation only; no change to what the guard sees or decides. Do this first. |
| 2 | Reuse the guard's fixed prompt prefix (template and framing) between requests instead of recomputing it | Removes the reading cost of the fixed text, a large share of the 14 s if reading dominates; verdicts unchanged because the guard reads the same tokens | Code change in `nasi_lemak/qwen3_local.py`. Needs confirming that the fixed text comes before the conversation in the rendered template, and identical verdicts on the evaluation corpus. |
| 3 | Check deny phrases before the input guard | Deny-phrase blocks drop from 5.5 s to milliseconds; allowed requests unchanged | Small code change in `nasi_lemak/gateway.py`. Both checks still run on every allowed request. |
| 4 | Shorter output framing, or send only the last turn to the output guard | Shorter output scan | Changes what the guard sees; needs a new accuracy evaluation before use. |
| 5 | Int8 quantisation of the guard, or a GPU | Large speed-up | Accuracy must be re-measured (quantisation), or new hardware. |

**Not recommended:** starting generation while the input guard is still running. It
would save about 2.7 s, but the model would see prompts that have not been screened,
which breaks the "screened before generation" control.

## Recommended order

1. Option 1 (measurement), then one live run to see where scan time goes.
2. Option 3 (small, no accuracy impact).
3. Option 2 if reading dominates, verified for identical verdicts.
4. Options 4 and 5 only if the pilot needs more, with a fresh accuracy evaluation.
   Thread tuning is already done: the guard uses all 4 cores.

No concurrent-load test has been run, and no latency target is agreed.
