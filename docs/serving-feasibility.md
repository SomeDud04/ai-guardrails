# Serving feasibility: evidence required

Status: blocked pending environment and approved artifacts. No real model loaded, hardware benchmark, endpoint inference, deployment or model download has been performed by this initial work.

The local preflight script is an inventory aid only. A detected executable or configured endpoint is not serving proof. Do not print endpoint credentials, fetch artifacts automatically, or send customer text during preflight.

## Ordered next checks

1. Name the customer owner, one application, target Linux distribution, CPU/RAM, GPU/VRAM and existing local generation endpoint. Confirm spare capacity and access by the approved integration operator.
2. Select exact generation, attack and output-safety model revisions; review licenses, access approvals and all runtime/container dependencies. Record immutable artifact digests before download/installation by the operator.
3. Test generation against the approved local endpoint with synthetic data. Record response shape, output cap and generation context window. Confirm endpoint and logs remain within the customer boundary.
4. Load the approved attack classifier through a verified serving adapter. Count the entire accepted conversation using its actual tokenizer and agreed serialization, including roles, separators and special tokens; reject overflow without truncation.
5. Load the chosen output-safety classifier. Define taxonomy and input template; prove that prompt plus buffered output fits its actual context window. Validate malformed responses and service deadlines.
6. Capture cold/warm stage timings and peak RAM/VRAM on named hardware; compare the same local generator without guards against the full guarded path. Measure resource contention, then five concurrent requests and bounded queues. The proposed 500 ms p95 added latency is unmeasured and remains subject to day-2 agreement.
7. Integrate the approved LiteLLM local route with logging/caching/telemetry controls and PostgreSQL audit. Exercise outage, audit-write failure and direct-route-bypass tests before marking the end-of-day-2 gate achieved.

## Current primary-source check

On 19 October 2026, Meta's [Prompt Guard 2 86M model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) describes a 512-token context window and Transformers classification interfaces. Its published evaluated-language list does not include BM or Chinese. This establishes candidate component constraints, not compatibility with this environment or measured protection.

The [LiteLLM guardrail quick start](https://docs.litellm.ai/docs/proxy/guardrails/quick_start) is the integration reference to validate when the route is implemented. No LiteLLM feature, edition, version or hook behavior has been exercised here. Pin selected versions and review relevant feature licensing before integration.

## Evidence record for real serving

Record date/operator; host OS/CPU/RAM/GPU/driver; exact model and tokenizer revisions/digests; runtime and dependency versions; license reviewer; endpoint boundary; synthetic fixture revision; complete token counts; generation cap; cold/warm timings; p50/p95/p99; memory peaks; concurrency/queue limits; failure counts; raw measurement artifact paths and reviewer disposition. Until these exist, keep serving and live-pilot gates open.
