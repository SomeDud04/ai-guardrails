# OWASP LLM Top 10 (2026) verification matrix

**Status:** scoped verification matrix for the current local gateway, not a
production certification and not a claim of complete OWASP coverage. The API
guard adapters, installer/Compose selection and guard-evaluation harness are
implemented and fixture-tested locally; live guard API acceptance, actual model
quality and held-out capacity remain pending. Inspected against source `1b0aa43` and committed
tests. Caller ran this turn: `python -m unittest tests.test_operator
tests.test_policy tests.test_chat_deadline -q` -> **51 tests in 3.961s, OK** on
synthetic local fixtures. The docs worker ran only documentation checks; no
live model, guard endpoint, PostgreSQL server, Docker daemon, scanner, package
install or VM was used.

Canonical mapping:
<https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/README.md>

The ten risks are: LLM01 prompt injection; LLM02 sensitive information
disclosure; LLM03 excessive agency; LLM04 supply chain; LLM05 data/model
poisoning; LLM06 unbounded consumption; LLM07 misinformation; LLM08 hidden
context exposure; LLM09 vector/embedding weaknesses; LLM10 improper output
handling.

## How to read this matrix

| Term | Meaning |
|---|---|
| **Covered (local synthetic)** | An existing test exercises the scoped behaviour with synthetic data, doubles or loopback fixtures. It is not live or independent evidence. |
| **Partial (local synthetic)** | Some local checks exist, but a material part of the risk is unverified or out of scope. |
| **Proposed (not implemented)** | A control or test is recommended. It has not been implemented and must not be reported as passing. |
| **Not applicable (architecture)** | The relevant component is absent. This is an applicability reason, not a pass. |
| **Pending** | Required proof is absent. |

Evidence constraints:

- Caller-run subset this turn (not the docs worker): `tests.test_operator
  tests.test_policy tests.test_chat_deadline` -> 51 tests in 3.961s, OK, synthetic
  local fixtures. Historical figures remain: 428 tests (426 passed, 2 real
  PostgreSQL skipped) and a 68-test focused checkpoint. None exercise tenancy,
  which is unimplemented.
- Most evidence is SQLite, deterministic guard/tokenizer doubles, loopback HTTP
  fixtures or static file parsing. No pretrained guard checkpoint has been
  executed here, and no live provider was contacted.
- Test mode (`NASI_LEMAK_MODE=test` plus the explicit
  `NASI_LEMAK_ALLOW_UNGUARDED_TEST=true` acknowledgement) keeps native guards
  inactive. The guarded path deliberately has no fake allow-all
  fallback, but guarded mode is not ready here without local guard artifacts,
  a valid policy, a configured model ID and PostgreSQL audit.
- A row marked covered covers only the stated check. It does not mean the whole
  OWASP risk is mitigated, that a customer deployment is approved, or that a
  downstream consumer is safe.

## LLM01: Prompt injection

Applies: yes. The public surface accepts free text in `user`, `assistant` and
`system` roles. A client-supplied `system` turn is accepted text, not a server
privilege.

| ID | What / where | How and expected result | Existing evidence | Pending proof | Applicability |
|---|---|---|---|---|---|
| OWASP-LLM01-01 | Strict text-only request shape in `nasi_lemak/gateway.py::Gateway._validate` and `nasi_lemak/server.py::_parse_json_object` | Send unknown top-level fields, `tools`, `policy`, `stream: true`, tool-role messages, non-string/multimodal content, duplicate JSON keys and more than 16 messages. Expect generic `400` before any provider or guard work. | `tests/test_gateway.py::test_rejects_unknown_fields_and_client_policy_override_before_upstream`, `test_gateway.py::test_rejects_invalid_roles_parts_limits_and_bool_tokens`; `tests/test_enforcement_integration.py::test_pre_generation_rejections_never_contact_upstream`; `tests/test_server.py::test_content_type_invalid_utf8_invalid_json_duplicate_keys_and_nan_are_rejected`, `test_server.py::test_unknown_fields_and_invalid_shapes_are_generic_400` | No live endpoint check; text payloads can still contain injection content, which the shape check does not classify. | Covered locally for shape only |
| OWASP-LLM01-02 | Mandatory full-conversation attack adapter before generation (`Gateway.handle`, `RealGatewayAdapters.scan_attack`) | Every original turn must reach the attack adapter, including `system` and `assistant` turns. An exception, malformed verdict or `block` decision must prevent generation and return generic `403`/`503`; test mode must be visibly inactive. | `tests/test_gateway.py::test_success_scans_each_original_turn_and_returns_masked_output`, `test_gateway.py::test_invalid_guard_result_fails_closed_without_leaking_content`; `tests/test_policy.py::test_guard_block_still_wins_and_deny_cannot_relax_it`; `tests/test_guard_wiring.py::test_full_serialization_uses_real_prompt_guard_tokenizer_and_rejects_over_512`; `tests/test_test_mode.py::test_default_guarded_without_checkpoints_is_unready`, `test_test_mode.py::test_guarded_loader_error_stays_unready_without_test_fallback` | Prompt Guard 2 API contract and runtime selection are implemented locally; threshold calibration, multilingual quality, held-out attack suite and live latency are unverified. Test-mode guards are inactive by design. | Partial; real classifier efficacy pending |
| OWASP-LLM01-03 | Literal server-side `deny_phrases` policy (`nasi_lemak/gateway.py::Policy.denies`, `nasi_lemak/policy.py`) | A literal case-insensitive substring in any accepted input turn or buffered output must block. It must not be represented as a semantic injection filter. | `tests/test_policy.py::test_every_input_turn_is_checked_before_generation`, `test_policy.py::test_buffered_output_is_checked_before_release_after_output_guard`, `test_policy.py::test_unicode_casefold_is_literal_and_not_a_regex` | No semantic injection coverage or independent phrase-list review. | Covered locally for literal policy only |
| OWASP-LLM01-04 | Buffered output safety gate and mandatory ordering (`Gateway.handle` output branch) | Unsafe or malformed output must release nothing; the output guard must run on the complete current-request context plus buffered output before terminal audit and release. | `tests/test_gateway.py::test_output_guard_block_and_malformed_results_release_nothing`, `test_gateway.py::test_audit_start_precedes_generation_and_terminal_precedes_release`; `tests/test_guard_wiring.py::test_unsafe_verdict_blocks_without_releasing_output`, `test_guard_wiring.py::test_guard_error_window_overflow_or_malformed_verdict_releases_nothing` | Qwen3Guard output API is selectable locally via the API backend; no live endpoint has been contacted. | Partial; synthetic guard wiring only |

## LLM02: Sensitive information disclosure

Applies: yes. The gateway handles request text, generated text, credentials,
audit metadata and tenant-scoped audit views.

| ID | What / where | How and expected result | Existing evidence | Pending proof | Applicability |
|---|---|---|---|---|---|
| OWASP-LLM02-01 | PII masking with exactly three ASCII format recognizers (`nasi_lemak/pii.py`: EMAIL, MY_PHONE, MYKAD) | Known synthetic formats must be masked in generation input, guard input where applicable, released output and audit-adjacent metadata. Expect no raw email/phone/MyKad in the captured sanitized request or response. | `tests/test_gateway.py::test_input_pii_and_output_pii_are_not_in_response_or_audit`; `tests/test_enforcement_integration.py::test_success_path_masks_pii_guards_and_audits_metadata_only`, `test_email_before_terminal_period_survives_assembled_masking`; `tests/test_pii.py::test_production_mask_outputs_are_unchanged_regressions`; `tests/test_pii_eval.py::test_real_evaluation_exit_is_nonzero_and_report_is_reproducible_without_raw_text`, `test_pii_eval.py::test_ambiguous_sku_is_honestly_counted_as_mykad_false_positive` | Only ASCII EMAIL/MY_PHONE/MYKAD regexes exist. Reviewed v2 still has **four labelled MyKad false positives** (order ID, SKU, part number, overlong phone-like value) and the gate remains **unaccepted**; semantic PII, passport, bank details, BM/Chinese text and independent human hold-out metrics are absent. See `docs/pii-quality.md` and `docs/language-support.md`. | Partial; only narrow format masking |
| OWASP-LLM02-02 | Metadata-only audit and generic error/log hygiene (`nasi_lemak/audit.py`, `nasi_lemak/gateway.py`, `nasi_lemak/server.py`, `nasi_lemak/generation.py`) | Audit rows must contain fixed policy/request metadata, not prompt or response text. Errors must not contain raw exception text, credentials, DSNs or provider bodies. Expected evidence is byte/row inspection, not a secrecy claim about host logs. | `tests/test_audit.py::test_records_initial_and_terminal_events`, `test_audit.py::test_terminal_event_inherits_original_policy_metadata`; `tests/test_gateway.py::test_input_pii_and_output_pii_are_not_in_response_or_audit`; `tests/test_generation.py::test_http_error_does_not_echo_secret_or_prompt_and_is_not_retried`, `test_generation.py::test_auth_none_omits_authorization_header_even_with_stale_key`; `tests/test_enforcement_integration.py::test_success_path_masks_pii_guards_and_audits_metadata_only` | No deployed log aggregation, crash-dump, proxy, provider or backup inspection. Those are outside this local slice. | Covered locally for the code path; deployment inspection pending |
| OWASP-LLM02-03 | Outbound data flow to generation and output-guard services (`nasi_lemak/generation.py`, `nasi_lemak/guard_api.py`) | Only the configured masked generation payload should go to the generation provider. A separate guard client, if used, has its own server-side endpoint and credential; it may receive the complete masked conversation plus raw buffered output, as documented. | `tests/test_generation.py::test_request_uses_prefix_headers_and_exact_payload`, `test_generation.py::test_only_masked_text_reaches_real_transport_and_alias_maps_to_upstream`; `tests/test_guard_api.py::test_safe_verdict_sends_full_context_and_guard_credentials`; `docs/guard-api-integration.md` | Real provider/guard data-flow approval, TLS endpoint verification, retention terms and live egress are pending. The guard API is optional and not runtime-selected. | Partial; documented, not live-approved |
| OWASP-LLM02-04 | Tenant and operator isolation in the proposed tenancy mode (`docs/demo-tenancy-design.md`) | A user key must chat only in its tenant; an operator key must list/export only its tenant; no global administrator; no tenant from payload/header. Expected local proof is concurrent cross-tenant responses/audit with no crossover. | Current single-application operator tests prove only one trusted `app_id` scope: `tests/test_operator.py::test_app_isolation_hides_other_application_rows`, `test_operator.py::test_chat_key_does_not_authorize_operator_events`, `test_operator.py::test_operator_key_does_not_authorize_chat`; `tests/test_export.py::test_export_read_is_one_bounded_app_scoped_select`. | Current single-application tenant-like operator scoping exists and is tested; the multi-tenant runtime (registry, per-user keys, per-tenant operator keys) is **proposed only** and not implemented. | Proposed; existing single-scope evidence |

## LLM03: Excessive agency

Applies: no tool, function, plugin, browser-action or approval surface exists in
this architecture. The strict text-only boundary is the relevant control.

| ID | What / where | How and expected result | Existing evidence | Pending proof | Applicability |
|---|---|---|---|---|---|
| OWASP-LLM03-01 | No tool/function/multimodal action surface (`Gateway._validate`, `generation._extract_content`) | `tools`, `tool_calls`, `function_call`, `tool` role, multimodal content and streaming must be rejected or refused; a provider response containing tool/function material must not be treated as usable output. | `tests/test_gateway.py::test_rejects_unknown_fields_and_client_policy_override_before_upstream`, `test_gateway.py::test_rejects_invalid_roles_parts_limits_and_bool_tokens`; `tests/test_enforcement_integration.py::test_pre_generation_rejections_never_contact_upstream`; `tests/test_generation.py::test_malformed_or_unsupported_completions_are_rejected` | If tools/actions are added later, a new authorization, approval and audit design is required. Not covered by this repository. | Not applicable (architecture); text boundary verified |
| OWASP-LLM03-02 | No autonomous action, approval or privileged-operation path | The gateway only returns text; it cannot execute a tool, change policy, write files or call an administrative API from model output. | Code inspection: `nasi_lemak/gateway.py` returns a chat completion object; no tool executor or plugin registry is imported. | Any future action surface needs a separate threat model and tests. | Not applicable (architecture) |

## LLM04: Supply chain

Applies: yes. The project builds a Python image, installs dependencies, uses base
images and expects operator-supplied model artifacts.

| ID | What / where | How and expected result | Existing evidence | Pending proof | Applicability |
|---|---|---|---|---|---|
| OWASP-LLM04-01 | Pinned Python extras, minimal image context and non-root runtime (`pyproject.toml`, `Dockerfile`) | Runtime should install the tested `server` extra, copy only `pyproject.toml` and `nasi_lemak/`, drop to UID/GID 10001 and avoid the optional ML extra in the default image. | `tests/test_container_config.py::test_base_stack_keeps_lightweight_safe_defaults`, `test_final_runtime_images_drop_to_non_root`, `test_minimal_copy_allowlist_has_no_workspace_wildcard`, `test_offline_flags_are_embodied_in_the_image` | No dependency lock file, SBOM, vulnerability scanner, license review or reproducible build was run. | Partial; static configuration only |
| OWASP-LLM04-02 | Base image integrity (`Dockerfile`, `compose.yaml`, `compose.demo.yaml`) | Tags should be immutable digests, signatures should be verified and scanner/SBOM gates should run before release. Current tags are mutable version/convenience tags. | `tests/test_container_config.py::test_base_stack_keeps_lightweight_safe_defaults`; `Dockerfile` uses `python:3.12-slim-bookworm`; `compose.yaml` uses `postgres:16.4-bookworm`; `compose.demo.yaml`/`docs/demo-access.md` use `nginx:stable-alpine` | **No scanner, SBOM, signature verification or immutable digest gate exists now.** Docker was not run here; no image was built. | Pending release gate |
| OWASP-LLM04-03 | Model artifact provenance and local-only loading (`nasi_lemak/guards.py`) | Guard weights must already exist locally; loading should use `local_files_only=True`, `token=False`, `trust_remote_code=False` and safetensors. Malformed/missing artifacts fail closed. | `tests/test_guards.py::test_prompt_loader_uses_local_only_flags_and_cpu`, `test_guards.py::test_llama_loader_uses_local_only_flags_and_cpu`, `test_guards.py::test_missing_directory_or_hub_identifier_fails_without_leaks`, `test_guards.py::test_no_verdict_is_returned_when_models_are_absent` | No artifact revision/hash allowlist, license acceptance, weight provenance, malware scan or real model load. The selected API-based guard plan also has no confirmed input contract. | Partial; local-only behaviour, provenance pending |

## LLM05: Data and model poisoning

| ID | What / where | How and expected result | Existing evidence | Pending proof | Applicability |
|---|---|---|---|---|---|
| OWASP-LLM05-01 | No training, fine-tuning or data-ingestion pipeline | There is no code path that trains, fine-tunes or ingests customer data into a model. Verify by code search and package inventory. | Source inspection: `nasi_lemak/` contains gateway, guards, generation, audit, policy and UI modules; no training/ingestion module. | A future training or feedback pipeline would need separate poisoning controls. Model weight integrity is covered as supply chain (LLM04-03), not as a pass here. | Not applicable (architecture) |
| OWASP-LLM05-02 | No retrieval corpus or vector index to poison | There is no retrieval, embedding store or document ingestion in the request path. | Source inspection: `GenerationClient.generate` sends a bounded chat payload only; no retrieval call. | If retrieval is added, a separate data-poisoning and provenance design is required. | Not applicable (architecture) |

## LLM06: Unbounded consumption

Applies: yes. The public chat path can consume CPU, provider tokens, audit I/O
and worker slots. Current controls are per-request and global; per-user quotas
are not implemented.

| ID | What / where | How and expected result | Existing evidence | Pending proof | Applicability |
|---|---|---|---|---|---|
| OWASP-LLM06-01 | Bounded body, JSON, message, turn and character input (`nasi_lemak/server.py`, `Gateway._validate`) | Oversized streamed bodies must be rejected without trusting `Content-Length`; malformed/duplicate JSON, more than 16 messages and a serialized conversation over 4096 characters must fail before generation. | `tests/test_server.py::test_streamed_body_over_limit_with_missing_content_length`, `test_streamed_body_over_limit_with_false_content_length`, `test_body_read_deadline_returns_503_without_calling_work`, `test_body_reader_capacity_is_bounded_before_streaming`; `tests/test_gateway.py::test_oversized_character_budget_returns_input_limit`; `tests/test_enforcement_integration.py::test_pre_generation_rejections_never_contact_upstream` | No OS/container-level network or disk quota proof; no live traffic. | Covered locally for request shape |
| OWASP-LLM06-02 | Token/count and provider-response output bounds (`Gateway.handle`, `nasi_lemak/generation.py`) | A token count over the policy budget must return `413`; `max_tokens` is bounded; the provider response has a byte cap and truncated/unsupported completions are rejected. | `tests/test_gateway.py::test_exact_token_coverage_is_required`, `test_gateway.py::test_oversized_character_budget_returns_input_limit`; `tests/test_enforcement_integration.py::test_exact_token_boundary_allows_full_content_and_rejects_one_over`; `tests/test_generation.py::test_oversized_invalid_json_and_invalid_utf8_are_rejected`, `test_generation.py::test_malformed_or_unsupported_completions_are_rejected` | Real tokenizer/guard and provider behaviour, model context limits and live output sizes are unverified. | Covered locally with doubles; live pending |
| OWASP-LLM06-03 | Concurrency and deadline admission (`nasi_lemak/server.py`, `tests/test_chat_deadline.py`) | Admission must be non-queuing; overload returns the existing `503`; an HTTP deadline must not release a worker slot early; late results must not be released. | `tests/test_server.py::test_overload_rejects_without_queue_and_slot_waits_for_cancelled_worker`; `tests/test_chat_deadline.py::test_overload_rejects_without_extra_dispatch_while_worker_runs`, `test_stalled_input_guard_returns_503_without_inference_and_late_work_continues`, `test_repeated_cancellation_past_shortened_deadline_sends_no_response` | No VM/CPU/model throughput measurement; no process-isolation or native hard deadline. | Covered locally; capacity evidence pending |
| OWASP-LLM06-04 | Per-user requests/minute and per-user/global in-flight demo limits | Proposed tenancy design: authenticated users get a fixed 60-second request window, a per-user in-flight cap and a shared global in-flight cap (tested at 10). Unknown identities must not allocate quota; 429 has a bounded `Retry-After`; global overload keeps `503`. | None implemented. The current server has only the shared chat admission semaphore and no per-user identity/quota. See `docs/demo-tenancy-design.md` sections 6-7. | Entire control is **proposed**; no code or test exists. It is a demo control, not a durable or production rate limit. | Proposed; not implemented |
| OWASP-LLM06-05 | Durable daily/token/currency budgets and cost caps | Not implemented and explicitly excluded from demo scope. No durable budget, cost accounting, chargeback or billing path exists; the UI must not claim them. | Source/configuration inspection; no budget or billing module. | Not proven inapplicable: a production deployment would still need durable budgets. Excluded here, not satisfied. | Excluded from demo scope; not implemented |
| OWASP-LLM06-06 | Reported long-prompt `503` reproduction | Reproduce the customer-reported long-prompt failure on the target VM/model and distinguish HTTP deadline, token budget, provider failure and guard failure. | The issue is documented as unresolved in `docs/demo-access.md` ("previously reported long-prompt `503`"). No fresh reproduction was performed. | Required separate VM/provider acceptance; do not infer a cause or fix from this matrix. | Pending |

## LLM07: Misinformation

Applies: yes, but factual/price verification is explicitly excluded pending an
authoritative reference dataset. Safety classification is not factuality.

| ID | What / where | How and expected result | Existing evidence | Pending proof | Applicability |
|---|---|---|---|---|---|
| OWASP-LLM07-01 | Factual and price claims | The gateway must not claim factual verification, price accuracy or an authoritative source. A factual evaluation requires an authoritative reference dataset and a reviewed method. | No factual-verification test exists. The demo page carries the disclaimer "Responses come from the configured model and may be inaccurate." `tests/test_demo_page.py::test_page_has_chat_shell_controls_status_and_separate_admin_link` asserts the page text. | Authoritative dataset, factual/price acceptance suite and customer sign-off are absent. | Out of scope; unverified |
| OWASP-LLM07-02 | Safety guard versus factuality | A `safe` safety verdict must not be presented as a factual-accuracy verdict. Output handling should keep those claims separate. | `docs/guard-api-integration.md` describes the Qwen safety verdict; the demo page (`nasi_lemak/demo_page.py`) is not claimed as a factual control. The guard adapter returns only `{"safe": bool}`. | No factuality classifier or benchmark exists. | Covered as a documentation boundary only |
| OWASP-LLM07-03 | Downstream reliance on generated claims | Integrators must treat generated text as untrusted and should not present it as verified advice or pricing. | UI disclaimer above; no integration contract for downstream factual use exists. | Downstream consumer acceptance and a product-specific disclaimer review are pending. | Partial; downstream contract pending |

## LLM08: Hidden context exposure

Applies: conditionally. The current gateway adds no hidden system prompt,
retrieval context or tool schema. Caller-supplied `system` text is ordinary
accepted input. If hidden context is added later, this section must be revisited.

| ID | What / where | How and expected result | Existing evidence | Pending proof | Applicability |
|---|---|---|---|---|---|
| OWASP-LLM08-01 | No server-only hidden prompt or retrieval context in the current request path (`Gateway.handle`, `GenerationClient.generate`) | Capture the upstream request and response; the payload should contain only the fixed model alias, the accepted messages, `max_tokens` and `stream: false`. No server instruction, policy text, retrieval document or hidden canary should be added or returned. | `tests/test_generation.py::test_request_uses_prefix_headers_and_exact_payload` asserts the exact payload; `tests/test_test_mode.py::test_real_client_reaches_mocked_upstream_with_exact_model_and_masks_pii` asserts the exact model/body. | A dedicated canary test is **proposed** (LLM08-03). No hidden context exists to test today; a future addition needs its own no-leak test. | Current architecture: no hidden context; canary proof pending |
| OWASP-LLM08-02 | Backend authentication independence | A user's gateway bearer must never become the upstream model or guard credential. In the runtime path, upstream auth comes only from server-side `NASI_LEMAK_GENERATION_*` configuration; explicit test/injected clients are separate. A separate guard client/credential must be independently configured, and a redirect must not forward credentials. | `tests/test_generation.py::test_request_uses_prefix_headers_and_exact_payload`, `test_generation.py::test_auth_none_omits_authorization_header_even_with_stale_key`, `test_generation.py::test_redirects_are_refused_without_forwarding_credentials`; `tests/test_guard_api.py::test_safe_verdict_sends_full_context_and_guard_credentials` uses a distinct guard key; `tests/test_guard_api.py::test_loopback_timeout_is_generic_without_retry_or_sensitive_detail` | Guard API runtime wiring, live provider authentication and a multi-tenant end-to-end canary capture are pending. | Covered locally for transport composition; live/tenancy pending |
| OWASP-LLM08-03 | Proposed canary/backend-auth independence regression | With two user keys and two operator keys, capture the upstream provider request, guard request and application logs. Expected: only the configured backend credentials appear; no user key, operator key, registry digest, hidden canary or operator-only metadata appears in the wrong request, response or log. | **None.** This test is proposed, not implemented. | Must be written with the tenancy implementation and run against a loopback fixture, then a reviewed live environment if live acceptance is separately authorized. | Proposed; not implemented |

## LLM09: Vector and embedding weaknesses

| ID | What / where | How and expected result | Existing evidence | Pending proof | Applicability |
|---|---|---|---|---|---|
| OWASP-LLM09-01 | No vector store, embedding generation or similarity retrieval | Confirm by source search that the request path has no embedding model, vector database, document loader or retrieval call. | Source inspection of `nasi_lemak/`: no embedding/vector/retrieval module or dependency. The gateway sends a bounded chat payload. | If retrieval or embeddings are introduced, a separate access-control, poisoning, inversion and tenant-isolation assessment is required. | Not applicable (architecture) |
| OWASP-LLM09-02 | No RAG ingestion path | No document ingestion, chunking, embedding write or tenant-index selection exists. | Source inspection; no ingestion CLI or dependency. | Same as above; future retrieval work. | Not applicable (architecture) |

## LLM10: Improper output handling

Applies: yes. Generated text is returned to a browser; CSV export contains audit
metadata only and never generated response text. Downstream consumers are
outside this repository.

| ID | What / where | How and expected result | Existing evidence | Pending proof | Applicability |
|---|---|---|---|---|---|
| OWASP-LLM10-01 | Buffer, guard, mask and audit before release (`Gateway.handle`) | No output may be released before the output guard and terminal audit succeed; unsafe/malformed output releases nothing; PII masking is applied before the client response. | `tests/test_gateway.py::test_output_guard_block_and_malformed_results_release_nothing`, `test_gateway.py::test_audit_start_precedes_generation_and_terminal_precedes_release`, `test_gateway.py::test_initial_or_terminal_audit_write_failure_withholds_output`; `tests/test_enforcement_integration.py::test_terminal_audit_write_failure_withholds_released_output`; `tests/test_guard_wiring.py::test_terminal_audit_failure_withholds_guarded_output` | Real output-guard model/API quality and live timeout behaviour are unverified. | Covered locally for ordering; real guard pending |
| OWASP-LLM10-02 | Browser rendering and client-side egress (`nasi_lemak/demo_page.py`, `tests/js/demo_page_harness.js`) | Model output containing HTML/script/event attributes should be rendered as text, create no elements, execute no script and trigger no navigation/subresource request. The key should stay in tab memory, not storage/cookies/console. | `tests/test_demo_js.py::test_demo_page_behavior` runs the extracted real script; harness scenarios include "plain-text response rendering" (an `<img onerror>`/`<script>` payload stays `textContent`), "key load clears input and claims no auth", "pagehide clears sensitive state" and the script's no-`localStorage`/`sessionStorage`/`document.cookie`/`console` check. `tests/test_demo_page.py::test_page_has_chat_shell_controls_status_and_separate_admin_link` asserts no `innerHTML` in the page. | This is Node.js with a deterministic DOM, not a real browser or CSP execution. A real-browser malicious-output/egress test is **proposed** (LLM10-04). | Partial; browser proof pending |
| OWASP-LLM10-03 | CSV export and spreadsheet formula handling (`nasi_lemak/export.py`) | Metadata cells beginning with `=`, `+`, `-`, `@`, control prefixes or whitespace-prefixed formula characters should be neutralized; the CSV should be bounded, app-scoped and metadata-only; generated response text, raw audit rows and secrets are never exported. | `tests/test_export.py::test_formula_and_text_cells_are_neutralized_without_db_mutation`, `test_export.py::test_formula_neutralization_is_strict_and_idempotent_after_apostrophe`, `test_export.py::test_export_read_is_one_bounded_app_scoped_select`; `tests/test_operator.py::test_event_text_is_json_only_and_not_reflected_into_shell` | No spreadsheet application or downstream CSV consumer was exercised. | Covered locally for encoding; consumer acceptance pending |
| OWASP-LLM10-04 | Malicious output and downstream-consumer egress | Proposed real-browser and downstream checks: render output containing `<img src=...>`, `<script>`, `javascript:` links and Markdown/HTML-like text; expect no network request, script execution or navigation. Downstream systems must treat model text as data, never as SQL/shell/HTML/code. | The local Node harness covers plain-text rendering; no downstream consumer test exists. | Entire egress/downstream contract is **proposed**. The gateway cannot sanitize a downstream consumer that chooses to interpret text as code. | Proposed; downstream limits explicit |
| OWASP-LLM10-05 | Unsupported tool/function output from a provider (`generation._extract_content`) | A provider response containing `tool_calls`, `function_call`, a refusal or a non-`stop` finish must be rejected rather than released as ordinary text. | `tests/test_generation.py::test_malformed_or_unsupported_completions_are_rejected` | No live provider shape check; provider contract is operator-configured. | Covered locally with fixtures; live pending |

## Corpus cross-reference (placeholder)

The frozen payload corpus under `evals/owasp/llm-top10-2026/` (128 records, see
`docs/owasp-corpus.md`) has no runner in this repository yet. This table is the
placeholder that will carry, per corpus id, the matrix row it exercises and the
recorded outcome once a runner exists. **Every outcome below is pending; no cell
is a pass.** Deterministic rows (`expect_status` in `{400, 413}`) already have
their current product limit and reproduction status recorded in
`evals/owasp/rebaseline-llm-top10-2026.json`; that map is input to the table, not
a substitute for a run.

| Corpus ids | Candidate matrix row(s) | Outcome |
|---|---|---|
| LLM01-001..020 | OWASP-LLM01-01, OWASP-LLM01-02, OWASP-LLM01-03, OWASP-LLM01-04 | Pending (no runner) |
| LLM02-001..016 | OWASP-LLM02-01, OWASP-LLM02-02, OWASP-LLM02-03, OWASP-LLM02-04 | Pending (no runner) |
| LLM03-001..008 | OWASP-LLM03-01, OWASP-LLM03-02 | Pending (no runner) |
| LLM04-001..007 | OWASP-LLM04-01, OWASP-LLM04-02, OWASP-LLM04-03 | Pending (no runner) |
| LLM05-001..005 | OWASP-LLM05-01, OWASP-LLM05-02 | Pending (no runner) |
| LLM06-001..012 | OWASP-LLM06-01, OWASP-LLM06-02, OWASP-LLM06-03, OWASP-LLM06-04, OWASP-LLM06-05, OWASP-LLM06-06 | Pending (no runner) |
| LLM07-001..009 | OWASP-LLM07-01, OWASP-LLM07-02, OWASP-LLM07-03 | Pending (no runner) |
| LLM08-001..014 | OWASP-LLM08-01, OWASP-LLM08-02, OWASP-LLM08-03 | Pending (no runner) |
| LLM09-001..006 | OWASP-LLM09-01, OWASP-LLM09-02 | Pending (no runner) |
| LLM10-001..013 | OWASP-LLM10-01, OWASP-LLM10-02, OWASP-LLM10-03, OWASP-LLM10-04, OWASP-LLM10-05 | Pending (no runner) |
| CTRL-001..018 | None yet: benign controls measure false positives on the same path and have no dedicated matrix row | Pending (no runner) |

## Cross-cutting limitations

- The matrix is scoped to the gateway, operator/export routes, demo page and
  container configuration in this repository. It does not cover the customer VM,
  hypervisor, LAN, nginx runtime, PostgreSQL server, provider infrastructure,
  model weights, guard service or downstream applications.
- There are no tools, training, ingestion, retrieval, vector store or embedding
  components. LLM03, LLM05 and LLM09 are therefore applicability findings, not
  claims that the underlying organisational risk is eliminated.
- Test-mode evidence must not be used as guarded-mode evidence. Test mode uses
  real generation transport but deliberately inactive native guard methods; the
  guarded path fails closed without local artifacts and has no fake fallback.
- The local guard/tokenizer evidence uses deterministic doubles. Prompt Guard 2
  and Qwen3Guard effectiveness, latency, memory use and multilingual coverage
  are not established here. The input classifier's hosted HTTP shape remains
  unconfirmed; this matrix does not invent one.
- The tenancy design, per-user quotas, tenant-scoped operator routes and canary
  test are **proposed only**. They must not be reported as implemented.
- The reported MyKad false positives remain unaccepted, and the reported
  long-prompt `503` is not reproduced in this docs slice.
- No real endpoint, account, package installation, scanner, SBOM, image build,
  Docker command, PostgreSQL command or VM command was used for this document.

## Validation performed for this document

- Caller-run (not the docs worker): `tests.test_operator tests.test_policy
  tests.test_chat_deadline` -> 51 passed in 3.961s on synthetic local fixtures.
- Docs worker: `git diff --check`, confirmed cited source files and test methods
  exist, and confirmed only the two requested docs changed. It did not rerun the
  runtime suite.
- Historical 428/426/2-skipped and 68-test checkpoint figures remain historical
  and do not validate tenancy or any proposed control.
