**Status:** maintained · **Kind:** reference · **Updated:** October 10, 2026 · **Governed by:** Elixir release 0.4.1 at 0a6568aa246326617f760e94e21b359285c6ddfc · **Review when:** the shared error vocabulary changes

# Error parity

OBSERVED: extraction with `REQUEST_SEAL_REPO=<reference-repo> node --experimental-strip-types --no-warnings scripts/extract-elixir-reasons.ts 0a6568aa246326617f760e94e21b359285c6ddfc <output.json>` reads pinned constructors and call sites through Git. Core and JOSE pairs follow helper arguments, defaults, guards, and variable bindings. Parameterized helper layers resolve only from bindings at actual call sites. The internal JOSE worker is called with the crypto layer, so JOSE deadline errors exist only on that layer. Structured Fields and Digest have open Elixir reason types: their reasons come from call sites; moduledoc lists only cross-check the extraction.

The error vocabulary is pinned to v0.4.1; the shared corpus stays at v0.4.0. The corpus index is byte-identical between those tags, and v0.4.1 supplied no corpus release assets. These pins track different artifacts.

Extension-profile reasons are defined by extension packages and arrive with the profile row. The core layer union does not include `profile`.

Errors are frozen plain objects, branded by a private WeakSet for their type. Fields mirror the corresponding Elixir struct, with `kind` as the discriminant. Core and Adapter generate a 16-character lowercase hex correlation; JOSE correlation is null. Other kinds carry no correlation. Core `message` is null except for `signer_algorithm_mismatch`, which uses "signer algorithm does not match signature specification". Core `source` is null except for handle `signing_failed`, where it carries a branded, bounded custody error; the outer retryable value remains false. Constructors are internal. Every constructor takes a per-kind reason literal union. An unknown runtime reason or an invalid core or JOSE (layer, reason) pair throws `TypeError`, a programmer error equivalent to Elixir's `FunctionClauseError`; it never silently substitutes another reason. This TypeScript vocabulary bounds even Elixir's open reason types to the pinned call sites.

Retryable rules: custody: `custody/custodian_unavailable`, `custody/deadline_exceeded`. · discovery: `discovery/cache_overloaded`, `discovery/connect_failed`, `discovery/deadline_exceeded`, `discovery/source_unavailable`. · discovery/unexpected_status: 500–599 (status-derived) · jose: `jose/deadline_exceeded`. All other retryable fields are false; reason-only structs have no retryable field.

Results are frozen on construction. `deepFreeze` returns a Result containing a snapshot of plain data structures. It freezes only the owned snapshot and never the caller's graph. Uint8Array children are copied and remain mutable because JavaScript cannot freeze nonempty typed arrays; accessors and other object types reject.

| Kind | Layer | Reason | Rule ID |
| --- | --- | --- | --- |
| core | binding | actor_unbound | core/binding.actor_unbound |
| core | binding | invalid_binding | core/binding.invalid_binding |
| core | binding | invalid_verification | core/binding.invalid_verification |
| core | binding | tenant_unbound | core/binding.tenant_unbound |
| core | binding | unattributed | core/binding.unattributed |
| core | content | body_unavailable | core/content.body_unavailable |
| core | content | digest_mismatch | core/content.digest_mismatch |
| core | content | digest_not_covered | core/content.digest_not_covered |
| core | content | digest_unsupported | core/content.digest_unsupported |
| core | crypto | invalid_signature | core/crypto.invalid_signature |
| core | crypto | signature_base_failed | core/crypto.signature_base_failed |
| core | crypto | signer_failed | core/crypto.signer_failed |
| core | crypto | signing_failed | core/crypto.signing_failed |
| core | crypto | verifier_failed | core/crypto.verifier_failed |
| core | fields | duplicate_label | core/fields.duplicate_label |
| core | fields | duplicate_parameter | core/fields.duplicate_parameter |
| core | fields | invalid_signature_agent | core/fields.invalid_signature_agent |
| core | fields | invalid_signature_field | core/fields.invalid_signature_field |
| core | fields | invalid_signature_input | core/fields.invalid_signature_input |
| core | fields | label_in_use | core/fields.label_in_use |
| core | fields | label_mismatch | core/fields.label_mismatch |
| core | fields | missing_signature | core/fields.missing_signature |
| core | fields | missing_signature_input | core/fields.missing_signature_input |
| core | fields | no_web_bot_auth_signature | core/fields.no_web_bot_auth_signature |
| core | fields | unknown_label | core/fields.unknown_label |
| core | freshness | created_in_future | core/freshness.created_in_future |
| core | freshness | expired | core/freshness.expired |
| core | freshness | invalid_clock | core/freshness.invalid_clock |
| core | freshness | lifetime_exceeded | core/freshness.lifetime_exceeded |
| core | freshness | missing_created | core/freshness.missing_created |
| core | freshness | missing_expires | core/freshness.missing_expires |
| core | freshness | too_old | core/freshness.too_old |
| core | input | algorithm_mismatch | core/input.algorithm_mismatch |
| core | input | invalid_message | core/input.invalid_message |
| core | input | invalid_options | core/input.invalid_options |
| core | input | invalid_policy | core/input.invalid_policy |
| core | input | invalid_profile | core/input.invalid_profile |
| core | input | invalid_quorum | core/input.invalid_quorum |
| core | input | invalid_request | core/input.invalid_request |
| core | input | limit | core/input.limit |
| core | input | signer_algorithm_mismatch | core/input.signer_algorithm_mismatch |
| core | input | unsupported_component | core/input.unsupported_component |
| core | key | agent_unresolved | core/key.agent_unresolved |
| core | key | key_resolver_failed | core/key.key_resolver_failed |
| core | key | unknown_key | core/key.unknown_key |
| core | negotiation | inapplicable_component | core/negotiation.inapplicable_component |
| core | negotiation | invalid_accept_signature | core/negotiation.invalid_accept_signature |
| core | negotiation | negotiation_unfulfillable | core/negotiation.negotiation_unfulfillable |
| core | negotiation | negotiation_unfulfilled | core/negotiation.negotiation_unfulfilled |
| core | policy | algorithm_mismatch | core/policy.algorithm_mismatch |
| core | policy | algorithm_not_permitted | core/policy.algorithm_not_permitted |
| core | policy | invalid_keyid | core/policy.invalid_keyid |
| core | policy | missing_required_component | core/policy.missing_required_component |
| core | policy | nested_coverage_incomplete | core/policy.nested_coverage_incomplete |
| core | policy | test_key_rejected | core/policy.test_key_rejected |
| core | policy | unexpected_component | core/policy.unexpected_component |
| core | policy | unexpected_signature | core/policy.unexpected_signature |
| core | quorum | ambiguous_key_identity | core/quorum.ambiguous_key_identity |
| core | quorum | binding_unsatisfied | core/quorum.binding_unsatisfied |
| core | quorum | nonqualifying_signature | core/quorum.nonqualifying_signature |
| core | quorum | quorum_not_met | core/quorum.quorum_not_met |
| core | quorum | unexpected_signature | core/quorum.unexpected_signature |
| core | replay | commitment_failed | core/replay.commitment_failed |
| core | replay | missing_replay_identifier | core/replay.missing_replay_identifier |
| core | replay | replayed | core/replay.replayed |
| core | replay | retention_exceeded | core/replay.retention_exceeded |
| core | replay | store_failed | core/replay.store_failed |
| core | replay | store_timeout | core/replay.store_timeout |
| core | replay | store_unavailable | core/replay.store_unavailable |
| message |  | invalid_body | message/invalid_body |
| message |  | invalid_field | message/invalid_field |
| message |  | invalid_message | message/invalid_message |
| message |  | invalid_transport | message/invalid_transport |
| structured_fields |  | duplicate_key | structured_fields/duplicate_key |
| structured_fields |  | duplicate_parameter | structured_fields/duplicate_parameter |
| structured_fields |  | invalid_field | structured_fields/invalid_field |
| structured_fields |  | invalid_limits | structured_fields/invalid_limits |
| structured_fields |  | invalid_message | structured_fields/invalid_message |
| structured_fields |  | invalid_schema | structured_fields/invalid_schema |
| structured_fields |  | invalid_value | structured_fields/invalid_value |
| structured_fields |  | limit | structured_fields/limit |
| structured_fields |  | missing_field | structured_fields/missing_field |
| structured_fields |  | revision_type | structured_fields/revision_type |
| structured_fields |  | schema_type | structured_fields/schema_type |
| structured_fields |  | syntax | structured_fields/syntax |
| structured_fields |  | unavailable_section | structured_fields/unavailable_section |
| signature_base |  | ambiguous_query_parameter | signature_base/ambiguous_query_parameter |
| signature_base |  | duplicate_component | signature_base/duplicate_component |
| signature_base |  | incompatible_parameters | signature_base/incompatible_parameters |
| signature_base |  | invalid_component | signature_base/invalid_component |
| signature_base |  | invalid_component_parameters | signature_base/invalid_component_parameters |
| signature_base |  | invalid_field_schema | signature_base/invalid_field_schema |
| signature_base |  | invalid_message | signature_base/invalid_message |
| signature_base |  | invalid_options | signature_base/invalid_options |
| signature_base |  | invalid_query_encoding | signature_base/invalid_query_encoding |
| signature_base |  | invalid_signature_parameters | signature_base/invalid_signature_parameters |
| signature_base |  | invalid_structured_field | signature_base/invalid_structured_field |
| signature_base |  | limit | signature_base/limit |
| signature_base |  | missing_dictionary_key | signature_base/missing_dictionary_key |
| signature_base |  | missing_field | signature_base/missing_field |
| signature_base |  | missing_query_parameter | signature_base/missing_query_parameter |
| signature_base |  | missing_request_context | signature_base/missing_request_context |
| signature_base |  | non_ascii | signature_base/non_ascii |
| signature_base |  | noncanonical_query_name | signature_base/noncanonical_query_name |
| signature_base |  | unavailable_origin | signature_base/unavailable_origin |
| signature_base |  | unavailable_trailers | signature_base/unavailable_trailers |
| signature_base |  | unknown_component | signature_base/unknown_component |
| signature_base |  | unknown_field_schema | signature_base/unknown_field_schema |
| signature_base |  | wrong_message_kind | signature_base/wrong_message_kind |
| digest |  | body_unavailable | digest/body_unavailable |
| digest |  | conflicting_digest | digest/conflicting_digest |
| digest |  | invalid_body | digest/invalid_body |
| digest |  | invalid_chunk | digest/invalid_chunk |
| digest |  | invalid_digest_length | digest/invalid_digest_length |
| digest |  | invalid_field | digest/invalid_field |
| digest |  | invalid_kind | digest/invalid_kind |
| digest |  | invalid_message | digest/invalid_message |
| digest |  | invalid_options | digest/invalid_options |
| digest |  | invalid_preference | digest/invalid_preference |
| digest |  | invalid_state | digest/invalid_state |
| digest |  | limit | digest/limit |
| digest |  | mismatch | digest/mismatch |
| digest |  | representation_required | digest/representation_required |
| digest |  | uncomputed_algorithm | digest/uncomputed_algorithm |
| digest |  | unsupported_algorithm | digest/unsupported_algorithm |
| crypto |  | invalid_data | crypto/invalid_data |
| crypto |  | invalid_key | crypto/invalid_key |
| crypto |  | invalid_options | crypto/invalid_options |
| crypto |  | invalid_signature | crypto/invalid_signature |
| crypto |  | key_mismatch | crypto/key_mismatch |
| crypto |  | unsupported_algorithm | crypto/unsupported_algorithm |
| crypto |  | unsupported_format | crypto/unsupported_format |
| custody |  | custodian_failure | custody/custodian_failure |
| custody |  | custodian_protocol | custody/custodian_protocol |
| custody |  | custodian_rejected | custody/custodian_rejected |
| custody |  | custodian_unavailable | custody/custodian_unavailable |
| custody |  | deadline_exceeded | custody/deadline_exceeded |
| custody |  | decryption_failed | custody/decryption_failed |
| custody |  | invalid_data | custody/invalid_data |
| custody |  | invalid_handle | custody/invalid_handle |
| custody |  | invalid_key | custody/invalid_key |
| custody |  | invalid_options | custody/invalid_options |
| custody |  | invalid_signature | custody/invalid_signature |
| custody |  | invalid_signing_output | custody/invalid_signing_output |
| custody |  | key_mismatch | custody/key_mismatch |
| custody |  | key_not_found | custody/key_not_found |
| custody |  | limit | custody/limit |
| custody |  | no_public_key | custody/no_public_key |
| custody |  | unsupported_algorithm | custody/unsupported_algorithm |
| custody |  | unsupported_format | custody/unsupported_format |
| custody |  | unsupported_operation | custody/unsupported_operation |
| discovery |  | address_denied | discovery/address_denied |
| discovery |  | ambiguous_key_source | discovery/ambiguous_key_source |
| discovery |  | cache_overloaded | discovery/cache_overloaded |
| discovery |  | client_id_mismatch | discovery/client_id_mismatch |
| discovery |  | connect_failed | discovery/connect_failed |
| discovery |  | deadline_exceeded | discovery/deadline_exceeded |
| discovery |  | directory_signature_invalid | discovery/directory_signature_invalid |
| discovery |  | directory_unsigned | discovery/directory_unsigned |
| discovery |  | invalid_key_set | discovery/invalid_key_set |
| discovery |  | invalid_options | discovery/invalid_options |
| discovery |  | invalid_response | discovery/invalid_response |
| discovery |  | invalid_source | discovery/invalid_source |
| discovery |  | limit | discovery/limit |
| discovery |  | redirect_denied | discovery/redirect_denied |
| discovery |  | redirect_limit | discovery/redirect_limit |
| discovery |  | resolution_failed | discovery/resolution_failed |
| discovery |  | revoked_key | discovery/revoked_key |
| discovery |  | source_unavailable | discovery/source_unavailable |
| discovery |  | tls_failed | discovery/tls_failed |
| discovery |  | transport_unavailable | discovery/transport_unavailable |
| discovery |  | unexpected_media_type | discovery/unexpected_media_type |
| discovery |  | unexpected_status | discovery/unexpected_status |
| discovery |  | unknown_key | discovery/unknown_key |
| jose | crypto | deadline_exceeded | jose/crypto.deadline_exceeded |
| jose | crypto | decryption_failed | jose/crypto.decryption_failed |
| jose | crypto | entropy_failure | jose/crypto.entropy_failure |
| jose | crypto | invalid_signature | jose/crypto.invalid_signature |
| jose | crypto | signer_failed | jose/crypto.signer_failed |
| jose | input | algorithm_not_permitted | jose/input.algorithm_not_permitted |
| jose | input | compression_unsupported | jose/input.compression_unsupported |
| jose | input | detached_payload | jose/input.detached_payload |
| jose | input | duplicate_member | jose/input.duplicate_member |
| jose | input | invalid_base64 | jose/input.invalid_base64 |
| jose | input | invalid_header | jose/input.invalid_header |
| jose | input | invalid_iv | jose/input.invalid_iv |
| jose | input | invalid_options | jose/input.invalid_options |
| jose | input | invalid_policy | jose/input.invalid_policy |
| jose | input | invalid_serialization | jose/input.invalid_serialization |
| jose | input | invalid_tag | jose/input.invalid_tag |
| jose | input | limit | jose/input.limit |
| jose | input | unsupported_critical_header | jose/input.unsupported_critical_header |
| jose | input | unsupported_header | jose/input.unsupported_header |
| jose | input | unsupported_serialization | jose/input.unsupported_serialization |
| jose | key | algorithm_mismatch | jose/key.algorithm_mismatch |
| jose | key | key_resolver_failed | jose/key.key_resolver_failed |
| jose | key | unknown_key | jose/key.unknown_key |
| jose | nesting | content_type_mismatch | jose/nesting.content_type_mismatch |
| jose | nesting | nesting_depth | jose/nesting.nesting_depth |
| replay |  | invalid_claim | replay/invalid_claim |
| replay |  | invalid_options | replay/invalid_options |
| replay |  | invalid_store | replay/invalid_store |
| replay |  | store_failed | replay/store_failed |
| replay |  | store_full | replay/store_full |
| replay |  | store_timeout | replay/store_timeout |
| replay |  | store_unavailable | replay/store_unavailable |
| adapter |  | already_verified | adapter/already_verified |
| adapter |  | body_unavailable | adapter/body_unavailable |
| adapter |  | cross_origin_redirect | adapter/cross_origin_redirect |
| adapter |  | digest_conflict | adapter/digest_conflict |
| adapter |  | invalid_options | adapter/invalid_options |
| adapter |  | invalid_request | adapter/invalid_request |
| adapter |  | limit | adapter/limit |
| adapter |  | not_captured | adapter/not_captured |
| adapter |  | not_final_step | adapter/not_final_step |
| adapter |  | parser_order | adapter/parser_order |
| adapter |  | request_rejected | adapter/request_rejected |
| adapter |  | response_rejected | adapter/response_rejected |
| adapter |  | signing_failed | adapter/signing_failed |
| adapter |  | unsupported_component | adapter/unsupported_component |
| adapter |  | unsupported_delivery | adapter/unsupported_delivery |
| adapter |  | untrusted_proxy | adapter/untrusted_proxy |
