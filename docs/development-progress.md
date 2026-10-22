# Development progress — 22 October 2026

Scope note: all entries distinguish local code/HTTP-fixture tests from
operator-reported VM deployment or generation, which was **not independently
verified in this workspace**. No overall completion percentage is claimed.

| # | Timeline item | State on 22 October 2026 | Evidence and remaining work |
|---|---|---|---|
| 1 | Environment | Local repository, Python virtualenv and loopback fixture tests run here. Docker is not installed in this workspace, so no image/Compose stack was built or started. | Local test suites and control docs. VM deployment/generation is operator-reported only. |
| 2 | Guard APIs | Optional API backend is implemented locally: input and output adapters, `NASI_LEMAK_GUARD_BACKEND=api` runtime selection, installer/Compose wiring and loopback fixture tests. Actual guard API acceptance, model quality and held-out capacity remain pending. | `nasi_lemak/guard_api.py`, `tests/test_guard_api.py`, `tests/test_guard_api_modes.py`, `compose.api.yaml`, `docs/guard-api-integration.md`. No live endpoint or pretrained API model was contacted. |
| 3 | Gateway + PII | Strict bearer auth, versioned YAML policy, literal deny phrases, EMAIL/MY_PHONE/MYKAD regex masking, ordered audit and bounded CSV export exist. Semantic PII and passport/bank recognizers are not covered. | The frozen v2 MyKad evaluation fails 95% precision with 4 false positives; do not claim customer-accepted accuracy. Long-prompt `503` remains unresolved. |
| 4 | Injection | Local Prompt Guard 2 attack adapter, policy deny phrases, `InputGuardApiAdapter` and gateway-owned v1 input-contract/runtime selection are implemented and fixture-tested. | Adapter and gateway runtime tests pass against loopback fixtures. A real compatible provider wrapper, threshold calibration and multilingual quality remain pending; the stock Prompt Guard adapter does not expose the hosted v1 contract. |
| 5 | Generation | Bounded OpenAI-compatible transport, auth modes, TLS/no-redirect and explicit insecure-HTTP opt-in are implemented. | Operator reported VM generation; not independently live-verified here. The confirmed endpoint/model ID is operator configuration. |
| 6 | Output | Local Llama Guard 3 contextual adapter exists. The Qwen3Guard API output adapter parses the complete verdict and fails closed, and the API backend now selects it under the guarded flow. | Fixture tests only; no Qwen endpoint or model was contacted, so no live quality or availability is claimed. The local backend still requires local guard artifacts; the API backend requires approved compatible guard APIs but no local guard artifacts. |
| 7 | UI | Professional Prompt testing plus Audit/events UI with synthetic samples, filtered decisions, a technical-detail toggle, CSV export and disconnect privacy. | Caller verified with synthetic data at desktop and 320px; not verified on the VM. |
| 8 | Accuracy / latency / concurrency | Synthetic regression and concurrency-isolation tests pass for the adapter, including a loopback transport-timeout regression; `nasi_lemak/guard_eval.py` adds a dry-run/execute synthetic smoke harness. | No live accuracy, latency, throughput or availability claim; the guard evaluation is plumbing evidence, not a held-out benchmark. Long-prompt `503` unresolved. |
| 9 | Tuning | Thresholds remain operator-supplied and uncalibrated; no model tuning was performed. | Prompt Guard threshold and Llama Guard context limit require approved artifacts and data. |
| 10 | Handover | README, guard wiring docs, environment examples, installer/runbooks and this dated progress note are present. | External acceptance, credentials and live evidence are still required. |

## Verification baseline

The historical baseline from the prior slice was **414 tests: 412 pass, 2
PostgreSQL integration skips** (`TEST_AUDIT_DSN` unset); that count is dated to
the prior slice, not the current release total. The final release suite is run
before push and recorded with the release result. This final patch ran these
focused suites with the workspace virtualenv:

| Suite | Result |
|---|---|
| `tests/test_guard_api.py` (13 existing + 1 loopback timeout regression) | 14 tests, all pass |
| `tests/test_demo_page.py` | 8 tests, all pass |
| `tests/test_demo_js.py` | 1 test, all pass |

All adapter tests use loopback `ThreadingHTTPServer` fixtures and synthetic
inputs. They are contract tests, not trained-model quality proof.

## Model-independent next steps

1. Repair MyKad recognizer precision for the four reviewed false positives
   (order ID, SKU, part number and an overlong phone-like value), then add a
   regression evaluation. Do not claim customer-accepted accuracy without an
   approved independent hold-out.
2. Confirm the input classifier contract with one actual response: exact served
   model ID, binary label/score shape, 512-token truncation/window behavior,
   authentication and timeouts. Then add the input adapter and explicit runtime
   wiring.
3. Confirm the Qwen3Guard served model ID/alias, endpoint and dedicated
   credential; run one supervised synthetic request, then decide whether to wire
   the prepared output adapter into startup. The selected deployment target is
   internal guard APIs, not local artifacts.
4. Resolve the long-prompt `503` behavior with an explicit bound and operator
   guidance.
5. Record deployment and real-model acceptance limits explicitly: the final
   release suite runs before push, VM/browser and native-model behavior remain
   separate evidence, and no live inference is implied by readiness.

## External acceptance dependencies

- Operator-provided generation and internal guard API endpoints, served model
  IDs and separate credentials. Local Prompt Guard/Llama Guard artifacts are
  required only by the current legacy guarded startup until API wiring exists.
- `TEST_AUDIT_DSN` for PostgreSQL integration coverage; Docker availability for
  image/Compose verification.
- Customer acceptance of data flow to any guard service before real content is
  submitted (including sensitive generated text sent to an output guard before
  release masking), and customer acceptance of accuracy/coverage limits.
