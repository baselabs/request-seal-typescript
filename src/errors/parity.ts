// Derived from pinned Elixir constructors and call sites; regenerate with scripts/generate-parity.ts or scripts/render-parity.ts --update-table.
export const ELIXIR_ERROR_PIN = '0a6568aa246326617f760e94e21b359285c6ddfc';
const entries = [
  {
    "kind": "core",
    "layer": "binding",
    "reason": "actor_unbound",
    "rule_id": "core/binding.actor_unbound"
  },
  {
    "kind": "core",
    "layer": "binding",
    "reason": "invalid_binding",
    "rule_id": "core/binding.invalid_binding"
  },
  {
    "kind": "core",
    "layer": "binding",
    "reason": "invalid_verification",
    "rule_id": "core/binding.invalid_verification"
  },
  {
    "kind": "core",
    "layer": "binding",
    "reason": "tenant_unbound",
    "rule_id": "core/binding.tenant_unbound"
  },
  {
    "kind": "core",
    "layer": "binding",
    "reason": "unattributed",
    "rule_id": "core/binding.unattributed"
  },
  {
    "kind": "core",
    "layer": "content",
    "reason": "body_unavailable",
    "rule_id": "core/content.body_unavailable"
  },
  {
    "kind": "core",
    "layer": "content",
    "reason": "digest_mismatch",
    "rule_id": "core/content.digest_mismatch"
  },
  {
    "kind": "core",
    "layer": "content",
    "reason": "digest_not_covered",
    "rule_id": "core/content.digest_not_covered"
  },
  {
    "kind": "core",
    "layer": "content",
    "reason": "digest_unsupported",
    "rule_id": "core/content.digest_unsupported"
  },
  {
    "kind": "core",
    "layer": "crypto",
    "reason": "invalid_signature",
    "rule_id": "core/crypto.invalid_signature"
  },
  {
    "kind": "core",
    "layer": "crypto",
    "reason": "signature_base_failed",
    "rule_id": "core/crypto.signature_base_failed"
  },
  {
    "kind": "core",
    "layer": "crypto",
    "reason": "signer_failed",
    "rule_id": "core/crypto.signer_failed"
  },
  {
    "kind": "core",
    "layer": "crypto",
    "reason": "signing_failed",
    "rule_id": "core/crypto.signing_failed"
  },
  {
    "kind": "core",
    "layer": "crypto",
    "reason": "verifier_failed",
    "rule_id": "core/crypto.verifier_failed"
  },
  {
    "kind": "core",
    "layer": "fields",
    "reason": "duplicate_label",
    "rule_id": "core/fields.duplicate_label"
  },
  {
    "kind": "core",
    "layer": "fields",
    "reason": "duplicate_parameter",
    "rule_id": "core/fields.duplicate_parameter"
  },
  {
    "kind": "core",
    "layer": "fields",
    "reason": "invalid_signature_agent",
    "rule_id": "core/fields.invalid_signature_agent"
  },
  {
    "kind": "core",
    "layer": "fields",
    "reason": "invalid_signature_field",
    "rule_id": "core/fields.invalid_signature_field"
  },
  {
    "kind": "core",
    "layer": "fields",
    "reason": "invalid_signature_input",
    "rule_id": "core/fields.invalid_signature_input"
  },
  {
    "kind": "core",
    "layer": "fields",
    "reason": "label_in_use",
    "rule_id": "core/fields.label_in_use"
  },
  {
    "kind": "core",
    "layer": "fields",
    "reason": "label_mismatch",
    "rule_id": "core/fields.label_mismatch"
  },
  {
    "kind": "core",
    "layer": "fields",
    "reason": "missing_signature",
    "rule_id": "core/fields.missing_signature"
  },
  {
    "kind": "core",
    "layer": "fields",
    "reason": "missing_signature_input",
    "rule_id": "core/fields.missing_signature_input"
  },
  {
    "kind": "core",
    "layer": "fields",
    "reason": "no_web_bot_auth_signature",
    "rule_id": "core/fields.no_web_bot_auth_signature"
  },
  {
    "kind": "core",
    "layer": "fields",
    "reason": "unknown_label",
    "rule_id": "core/fields.unknown_label"
  },
  {
    "kind": "core",
    "layer": "freshness",
    "reason": "created_in_future",
    "rule_id": "core/freshness.created_in_future"
  },
  {
    "kind": "core",
    "layer": "freshness",
    "reason": "expired",
    "rule_id": "core/freshness.expired"
  },
  {
    "kind": "core",
    "layer": "freshness",
    "reason": "invalid_clock",
    "rule_id": "core/freshness.invalid_clock"
  },
  {
    "kind": "core",
    "layer": "freshness",
    "reason": "lifetime_exceeded",
    "rule_id": "core/freshness.lifetime_exceeded"
  },
  {
    "kind": "core",
    "layer": "freshness",
    "reason": "missing_created",
    "rule_id": "core/freshness.missing_created"
  },
  {
    "kind": "core",
    "layer": "freshness",
    "reason": "missing_expires",
    "rule_id": "core/freshness.missing_expires"
  },
  {
    "kind": "core",
    "layer": "freshness",
    "reason": "too_old",
    "rule_id": "core/freshness.too_old"
  },
  {
    "kind": "core",
    "layer": "input",
    "reason": "algorithm_mismatch",
    "rule_id": "core/input.algorithm_mismatch"
  },
  {
    "kind": "core",
    "layer": "input",
    "reason": "invalid_message",
    "rule_id": "core/input.invalid_message"
  },
  {
    "kind": "core",
    "layer": "input",
    "reason": "invalid_options",
    "rule_id": "core/input.invalid_options"
  },
  {
    "kind": "core",
    "layer": "input",
    "reason": "invalid_policy",
    "rule_id": "core/input.invalid_policy"
  },
  {
    "kind": "core",
    "layer": "input",
    "reason": "invalid_profile",
    "rule_id": "core/input.invalid_profile"
  },
  {
    "kind": "core",
    "layer": "input",
    "reason": "invalid_quorum",
    "rule_id": "core/input.invalid_quorum"
  },
  {
    "kind": "core",
    "layer": "input",
    "reason": "invalid_request",
    "rule_id": "core/input.invalid_request"
  },
  {
    "kind": "core",
    "layer": "input",
    "reason": "limit",
    "rule_id": "core/input.limit"
  },
  {
    "kind": "core",
    "layer": "input",
    "reason": "signer_algorithm_mismatch",
    "rule_id": "core/input.signer_algorithm_mismatch"
  },
  {
    "kind": "core",
    "layer": "input",
    "reason": "unsupported_component",
    "rule_id": "core/input.unsupported_component"
  },
  {
    "kind": "core",
    "layer": "key",
    "reason": "agent_unresolved",
    "rule_id": "core/key.agent_unresolved"
  },
  {
    "kind": "core",
    "layer": "key",
    "reason": "key_resolver_failed",
    "rule_id": "core/key.key_resolver_failed"
  },
  {
    "kind": "core",
    "layer": "key",
    "reason": "unknown_key",
    "rule_id": "core/key.unknown_key"
  },
  {
    "kind": "core",
    "layer": "negotiation",
    "reason": "inapplicable_component",
    "rule_id": "core/negotiation.inapplicable_component"
  },
  {
    "kind": "core",
    "layer": "negotiation",
    "reason": "invalid_accept_signature",
    "rule_id": "core/negotiation.invalid_accept_signature"
  },
  {
    "kind": "core",
    "layer": "negotiation",
    "reason": "negotiation_unfulfillable",
    "rule_id": "core/negotiation.negotiation_unfulfillable"
  },
  {
    "kind": "core",
    "layer": "negotiation",
    "reason": "negotiation_unfulfilled",
    "rule_id": "core/negotiation.negotiation_unfulfilled"
  },
  {
    "kind": "core",
    "layer": "policy",
    "reason": "algorithm_mismatch",
    "rule_id": "core/policy.algorithm_mismatch"
  },
  {
    "kind": "core",
    "layer": "policy",
    "reason": "algorithm_not_permitted",
    "rule_id": "core/policy.algorithm_not_permitted"
  },
  {
    "kind": "core",
    "layer": "policy",
    "reason": "invalid_keyid",
    "rule_id": "core/policy.invalid_keyid"
  },
  {
    "kind": "core",
    "layer": "policy",
    "reason": "missing_required_component",
    "rule_id": "core/policy.missing_required_component"
  },
  {
    "kind": "core",
    "layer": "policy",
    "reason": "nested_coverage_incomplete",
    "rule_id": "core/policy.nested_coverage_incomplete"
  },
  {
    "kind": "core",
    "layer": "policy",
    "reason": "test_key_rejected",
    "rule_id": "core/policy.test_key_rejected"
  },
  {
    "kind": "core",
    "layer": "policy",
    "reason": "unexpected_component",
    "rule_id": "core/policy.unexpected_component"
  },
  {
    "kind": "core",
    "layer": "policy",
    "reason": "unexpected_signature",
    "rule_id": "core/policy.unexpected_signature"
  },
  {
    "kind": "core",
    "layer": "quorum",
    "reason": "ambiguous_key_identity",
    "rule_id": "core/quorum.ambiguous_key_identity"
  },
  {
    "kind": "core",
    "layer": "quorum",
    "reason": "binding_unsatisfied",
    "rule_id": "core/quorum.binding_unsatisfied"
  },
  {
    "kind": "core",
    "layer": "quorum",
    "reason": "nonqualifying_signature",
    "rule_id": "core/quorum.nonqualifying_signature"
  },
  {
    "kind": "core",
    "layer": "quorum",
    "reason": "quorum_not_met",
    "rule_id": "core/quorum.quorum_not_met"
  },
  {
    "kind": "core",
    "layer": "quorum",
    "reason": "unexpected_signature",
    "rule_id": "core/quorum.unexpected_signature"
  },
  {
    "kind": "core",
    "layer": "replay",
    "reason": "commitment_failed",
    "rule_id": "core/replay.commitment_failed"
  },
  {
    "kind": "core",
    "layer": "replay",
    "reason": "missing_replay_identifier",
    "rule_id": "core/replay.missing_replay_identifier"
  },
  {
    "kind": "core",
    "layer": "replay",
    "reason": "replayed",
    "rule_id": "core/replay.replayed"
  },
  {
    "kind": "core",
    "layer": "replay",
    "reason": "retention_exceeded",
    "rule_id": "core/replay.retention_exceeded"
  },
  {
    "kind": "core",
    "layer": "replay",
    "reason": "store_failed",
    "rule_id": "core/replay.store_failed"
  },
  {
    "kind": "core",
    "layer": "replay",
    "reason": "store_timeout",
    "rule_id": "core/replay.store_timeout"
  },
  {
    "kind": "core",
    "layer": "replay",
    "reason": "store_unavailable",
    "rule_id": "core/replay.store_unavailable"
  },
  {
    "kind": "message",
    "reason": "invalid_body",
    "rule_id": "message/invalid_body"
  },
  {
    "kind": "message",
    "reason": "invalid_field",
    "rule_id": "message/invalid_field"
  },
  {
    "kind": "message",
    "reason": "invalid_message",
    "rule_id": "message/invalid_message"
  },
  {
    "kind": "message",
    "reason": "invalid_transport",
    "rule_id": "message/invalid_transport"
  },
  {
    "kind": "structured_fields",
    "reason": "duplicate_key",
    "rule_id": "structured_fields/duplicate_key"
  },
  {
    "kind": "structured_fields",
    "reason": "duplicate_parameter",
    "rule_id": "structured_fields/duplicate_parameter"
  },
  {
    "kind": "structured_fields",
    "reason": "invalid_field",
    "rule_id": "structured_fields/invalid_field"
  },
  {
    "kind": "structured_fields",
    "reason": "invalid_limits",
    "rule_id": "structured_fields/invalid_limits"
  },
  {
    "kind": "structured_fields",
    "reason": "invalid_message",
    "rule_id": "structured_fields/invalid_message"
  },
  {
    "kind": "structured_fields",
    "reason": "invalid_schema",
    "rule_id": "structured_fields/invalid_schema"
  },
  {
    "kind": "structured_fields",
    "reason": "invalid_value",
    "rule_id": "structured_fields/invalid_value"
  },
  {
    "kind": "structured_fields",
    "reason": "limit",
    "rule_id": "structured_fields/limit"
  },
  {
    "kind": "structured_fields",
    "reason": "missing_field",
    "rule_id": "structured_fields/missing_field"
  },
  {
    "kind": "structured_fields",
    "reason": "revision_type",
    "rule_id": "structured_fields/revision_type"
  },
  {
    "kind": "structured_fields",
    "reason": "schema_type",
    "rule_id": "structured_fields/schema_type"
  },
  {
    "kind": "structured_fields",
    "reason": "syntax",
    "rule_id": "structured_fields/syntax"
  },
  {
    "kind": "structured_fields",
    "reason": "unavailable_section",
    "rule_id": "structured_fields/unavailable_section"
  },
  {
    "kind": "signature_base",
    "reason": "ambiguous_query_parameter",
    "rule_id": "signature_base/ambiguous_query_parameter"
  },
  {
    "kind": "signature_base",
    "reason": "duplicate_component",
    "rule_id": "signature_base/duplicate_component"
  },
  {
    "kind": "signature_base",
    "reason": "incompatible_parameters",
    "rule_id": "signature_base/incompatible_parameters"
  },
  {
    "kind": "signature_base",
    "reason": "invalid_component",
    "rule_id": "signature_base/invalid_component"
  },
  {
    "kind": "signature_base",
    "reason": "invalid_component_parameters",
    "rule_id": "signature_base/invalid_component_parameters"
  },
  {
    "kind": "signature_base",
    "reason": "invalid_field_schema",
    "rule_id": "signature_base/invalid_field_schema"
  },
  {
    "kind": "signature_base",
    "reason": "invalid_message",
    "rule_id": "signature_base/invalid_message"
  },
  {
    "kind": "signature_base",
    "reason": "invalid_options",
    "rule_id": "signature_base/invalid_options"
  },
  {
    "kind": "signature_base",
    "reason": "invalid_query_encoding",
    "rule_id": "signature_base/invalid_query_encoding"
  },
  {
    "kind": "signature_base",
    "reason": "invalid_signature_parameters",
    "rule_id": "signature_base/invalid_signature_parameters"
  },
  {
    "kind": "signature_base",
    "reason": "invalid_structured_field",
    "rule_id": "signature_base/invalid_structured_field"
  },
  {
    "kind": "signature_base",
    "reason": "limit",
    "rule_id": "signature_base/limit"
  },
  {
    "kind": "signature_base",
    "reason": "missing_dictionary_key",
    "rule_id": "signature_base/missing_dictionary_key"
  },
  {
    "kind": "signature_base",
    "reason": "missing_field",
    "rule_id": "signature_base/missing_field"
  },
  {
    "kind": "signature_base",
    "reason": "missing_query_parameter",
    "rule_id": "signature_base/missing_query_parameter"
  },
  {
    "kind": "signature_base",
    "reason": "missing_request_context",
    "rule_id": "signature_base/missing_request_context"
  },
  {
    "kind": "signature_base",
    "reason": "non_ascii",
    "rule_id": "signature_base/non_ascii"
  },
  {
    "kind": "signature_base",
    "reason": "noncanonical_query_name",
    "rule_id": "signature_base/noncanonical_query_name"
  },
  {
    "kind": "signature_base",
    "reason": "unavailable_origin",
    "rule_id": "signature_base/unavailable_origin"
  },
  {
    "kind": "signature_base",
    "reason": "unavailable_trailers",
    "rule_id": "signature_base/unavailable_trailers"
  },
  {
    "kind": "signature_base",
    "reason": "unknown_component",
    "rule_id": "signature_base/unknown_component"
  },
  {
    "kind": "signature_base",
    "reason": "unknown_field_schema",
    "rule_id": "signature_base/unknown_field_schema"
  },
  {
    "kind": "signature_base",
    "reason": "wrong_message_kind",
    "rule_id": "signature_base/wrong_message_kind"
  },
  {
    "kind": "digest",
    "reason": "body_unavailable",
    "rule_id": "digest/body_unavailable"
  },
  {
    "kind": "digest",
    "reason": "conflicting_digest",
    "rule_id": "digest/conflicting_digest"
  },
  {
    "kind": "digest",
    "reason": "invalid_body",
    "rule_id": "digest/invalid_body"
  },
  {
    "kind": "digest",
    "reason": "invalid_chunk",
    "rule_id": "digest/invalid_chunk"
  },
  {
    "kind": "digest",
    "reason": "invalid_digest_length",
    "rule_id": "digest/invalid_digest_length"
  },
  {
    "kind": "digest",
    "reason": "invalid_field",
    "rule_id": "digest/invalid_field"
  },
  {
    "kind": "digest",
    "reason": "invalid_kind",
    "rule_id": "digest/invalid_kind"
  },
  {
    "kind": "digest",
    "reason": "invalid_message",
    "rule_id": "digest/invalid_message"
  },
  {
    "kind": "digest",
    "reason": "invalid_options",
    "rule_id": "digest/invalid_options"
  },
  {
    "kind": "digest",
    "reason": "invalid_preference",
    "rule_id": "digest/invalid_preference"
  },
  {
    "kind": "digest",
    "reason": "invalid_state",
    "rule_id": "digest/invalid_state"
  },
  {
    "kind": "digest",
    "reason": "limit",
    "rule_id": "digest/limit"
  },
  {
    "kind": "digest",
    "reason": "mismatch",
    "rule_id": "digest/mismatch"
  },
  {
    "kind": "digest",
    "reason": "representation_required",
    "rule_id": "digest/representation_required"
  },
  {
    "kind": "digest",
    "reason": "uncomputed_algorithm",
    "rule_id": "digest/uncomputed_algorithm"
  },
  {
    "kind": "digest",
    "reason": "unsupported_algorithm",
    "rule_id": "digest/unsupported_algorithm"
  },
  {
    "kind": "crypto",
    "reason": "invalid_data",
    "rule_id": "crypto/invalid_data"
  },
  {
    "kind": "crypto",
    "reason": "invalid_key",
    "rule_id": "crypto/invalid_key"
  },
  {
    "kind": "crypto",
    "reason": "invalid_options",
    "rule_id": "crypto/invalid_options"
  },
  {
    "kind": "crypto",
    "reason": "invalid_signature",
    "rule_id": "crypto/invalid_signature"
  },
  {
    "kind": "crypto",
    "reason": "key_mismatch",
    "rule_id": "crypto/key_mismatch"
  },
  {
    "kind": "crypto",
    "reason": "unsupported_algorithm",
    "rule_id": "crypto/unsupported_algorithm"
  },
  {
    "kind": "crypto",
    "reason": "unsupported_format",
    "rule_id": "crypto/unsupported_format"
  },
  {
    "kind": "custody",
    "reason": "custodian_failure",
    "rule_id": "custody/custodian_failure"
  },
  {
    "kind": "custody",
    "reason": "custodian_protocol",
    "rule_id": "custody/custodian_protocol"
  },
  {
    "kind": "custody",
    "reason": "custodian_rejected",
    "rule_id": "custody/custodian_rejected"
  },
  {
    "kind": "custody",
    "reason": "custodian_unavailable",
    "rule_id": "custody/custodian_unavailable"
  },
  {
    "kind": "custody",
    "reason": "deadline_exceeded",
    "rule_id": "custody/deadline_exceeded"
  },
  {
    "kind": "custody",
    "reason": "decryption_failed",
    "rule_id": "custody/decryption_failed"
  },
  {
    "kind": "custody",
    "reason": "invalid_data",
    "rule_id": "custody/invalid_data"
  },
  {
    "kind": "custody",
    "reason": "invalid_handle",
    "rule_id": "custody/invalid_handle"
  },
  {
    "kind": "custody",
    "reason": "invalid_key",
    "rule_id": "custody/invalid_key"
  },
  {
    "kind": "custody",
    "reason": "invalid_options",
    "rule_id": "custody/invalid_options"
  },
  {
    "kind": "custody",
    "reason": "invalid_signature",
    "rule_id": "custody/invalid_signature"
  },
  {
    "kind": "custody",
    "reason": "invalid_signing_output",
    "rule_id": "custody/invalid_signing_output"
  },
  {
    "kind": "custody",
    "reason": "key_mismatch",
    "rule_id": "custody/key_mismatch"
  },
  {
    "kind": "custody",
    "reason": "key_not_found",
    "rule_id": "custody/key_not_found"
  },
  {
    "kind": "custody",
    "reason": "limit",
    "rule_id": "custody/limit"
  },
  {
    "kind": "custody",
    "reason": "no_public_key",
    "rule_id": "custody/no_public_key"
  },
  {
    "kind": "custody",
    "reason": "unsupported_algorithm",
    "rule_id": "custody/unsupported_algorithm"
  },
  {
    "kind": "custody",
    "reason": "unsupported_format",
    "rule_id": "custody/unsupported_format"
  },
  {
    "kind": "custody",
    "reason": "unsupported_operation",
    "rule_id": "custody/unsupported_operation"
  },
  {
    "kind": "discovery",
    "reason": "address_denied",
    "rule_id": "discovery/address_denied"
  },
  {
    "kind": "discovery",
    "reason": "ambiguous_key_source",
    "rule_id": "discovery/ambiguous_key_source"
  },
  {
    "kind": "discovery",
    "reason": "cache_overloaded",
    "rule_id": "discovery/cache_overloaded"
  },
  {
    "kind": "discovery",
    "reason": "client_id_mismatch",
    "rule_id": "discovery/client_id_mismatch"
  },
  {
    "kind": "discovery",
    "reason": "connect_failed",
    "rule_id": "discovery/connect_failed"
  },
  {
    "kind": "discovery",
    "reason": "deadline_exceeded",
    "rule_id": "discovery/deadline_exceeded"
  },
  {
    "kind": "discovery",
    "reason": "directory_signature_invalid",
    "rule_id": "discovery/directory_signature_invalid"
  },
  {
    "kind": "discovery",
    "reason": "directory_unsigned",
    "rule_id": "discovery/directory_unsigned"
  },
  {
    "kind": "discovery",
    "reason": "invalid_key_set",
    "rule_id": "discovery/invalid_key_set"
  },
  {
    "kind": "discovery",
    "reason": "invalid_options",
    "rule_id": "discovery/invalid_options"
  },
  {
    "kind": "discovery",
    "reason": "invalid_response",
    "rule_id": "discovery/invalid_response"
  },
  {
    "kind": "discovery",
    "reason": "invalid_source",
    "rule_id": "discovery/invalid_source"
  },
  {
    "kind": "discovery",
    "reason": "limit",
    "rule_id": "discovery/limit"
  },
  {
    "kind": "discovery",
    "reason": "redirect_denied",
    "rule_id": "discovery/redirect_denied"
  },
  {
    "kind": "discovery",
    "reason": "redirect_limit",
    "rule_id": "discovery/redirect_limit"
  },
  {
    "kind": "discovery",
    "reason": "resolution_failed",
    "rule_id": "discovery/resolution_failed"
  },
  {
    "kind": "discovery",
    "reason": "revoked_key",
    "rule_id": "discovery/revoked_key"
  },
  {
    "kind": "discovery",
    "reason": "source_unavailable",
    "rule_id": "discovery/source_unavailable"
  },
  {
    "kind": "discovery",
    "reason": "tls_failed",
    "rule_id": "discovery/tls_failed"
  },
  {
    "kind": "discovery",
    "reason": "transport_unavailable",
    "rule_id": "discovery/transport_unavailable"
  },
  {
    "kind": "discovery",
    "reason": "unexpected_media_type",
    "rule_id": "discovery/unexpected_media_type"
  },
  {
    "kind": "discovery",
    "reason": "unexpected_status",
    "rule_id": "discovery/unexpected_status"
  },
  {
    "kind": "discovery",
    "reason": "unknown_key",
    "rule_id": "discovery/unknown_key"
  },
  {
    "kind": "jose",
    "layer": "crypto",
    "reason": "deadline_exceeded",
    "rule_id": "jose/crypto.deadline_exceeded"
  },
  {
    "kind": "jose",
    "layer": "crypto",
    "reason": "decryption_failed",
    "rule_id": "jose/crypto.decryption_failed"
  },
  {
    "kind": "jose",
    "layer": "crypto",
    "reason": "entropy_failure",
    "rule_id": "jose/crypto.entropy_failure"
  },
  {
    "kind": "jose",
    "layer": "crypto",
    "reason": "invalid_signature",
    "rule_id": "jose/crypto.invalid_signature"
  },
  {
    "kind": "jose",
    "layer": "crypto",
    "reason": "signer_failed",
    "rule_id": "jose/crypto.signer_failed"
  },
  {
    "kind": "jose",
    "layer": "input",
    "reason": "algorithm_not_permitted",
    "rule_id": "jose/input.algorithm_not_permitted"
  },
  {
    "kind": "jose",
    "layer": "input",
    "reason": "compression_unsupported",
    "rule_id": "jose/input.compression_unsupported"
  },
  {
    "kind": "jose",
    "layer": "input",
    "reason": "detached_payload",
    "rule_id": "jose/input.detached_payload"
  },
  {
    "kind": "jose",
    "layer": "input",
    "reason": "duplicate_member",
    "rule_id": "jose/input.duplicate_member"
  },
  {
    "kind": "jose",
    "layer": "input",
    "reason": "invalid_base64",
    "rule_id": "jose/input.invalid_base64"
  },
  {
    "kind": "jose",
    "layer": "input",
    "reason": "invalid_header",
    "rule_id": "jose/input.invalid_header"
  },
  {
    "kind": "jose",
    "layer": "input",
    "reason": "invalid_iv",
    "rule_id": "jose/input.invalid_iv"
  },
  {
    "kind": "jose",
    "layer": "input",
    "reason": "invalid_options",
    "rule_id": "jose/input.invalid_options"
  },
  {
    "kind": "jose",
    "layer": "input",
    "reason": "invalid_policy",
    "rule_id": "jose/input.invalid_policy"
  },
  {
    "kind": "jose",
    "layer": "input",
    "reason": "invalid_serialization",
    "rule_id": "jose/input.invalid_serialization"
  },
  {
    "kind": "jose",
    "layer": "input",
    "reason": "invalid_tag",
    "rule_id": "jose/input.invalid_tag"
  },
  {
    "kind": "jose",
    "layer": "input",
    "reason": "limit",
    "rule_id": "jose/input.limit"
  },
  {
    "kind": "jose",
    "layer": "input",
    "reason": "unsupported_critical_header",
    "rule_id": "jose/input.unsupported_critical_header"
  },
  {
    "kind": "jose",
    "layer": "input",
    "reason": "unsupported_header",
    "rule_id": "jose/input.unsupported_header"
  },
  {
    "kind": "jose",
    "layer": "input",
    "reason": "unsupported_serialization",
    "rule_id": "jose/input.unsupported_serialization"
  },
  {
    "kind": "jose",
    "layer": "key",
    "reason": "algorithm_mismatch",
    "rule_id": "jose/key.algorithm_mismatch"
  },
  {
    "kind": "jose",
    "layer": "key",
    "reason": "key_resolver_failed",
    "rule_id": "jose/key.key_resolver_failed"
  },
  {
    "kind": "jose",
    "layer": "key",
    "reason": "unknown_key",
    "rule_id": "jose/key.unknown_key"
  },
  {
    "kind": "jose",
    "layer": "nesting",
    "reason": "content_type_mismatch",
    "rule_id": "jose/nesting.content_type_mismatch"
  },
  {
    "kind": "jose",
    "layer": "nesting",
    "reason": "nesting_depth",
    "rule_id": "jose/nesting.nesting_depth"
  },
  {
    "kind": "replay",
    "reason": "invalid_claim",
    "rule_id": "replay/invalid_claim"
  },
  {
    "kind": "replay",
    "reason": "invalid_options",
    "rule_id": "replay/invalid_options"
  },
  {
    "kind": "replay",
    "reason": "invalid_store",
    "rule_id": "replay/invalid_store"
  },
  {
    "kind": "replay",
    "reason": "store_failed",
    "rule_id": "replay/store_failed"
  },
  {
    "kind": "replay",
    "reason": "store_full",
    "rule_id": "replay/store_full"
  },
  {
    "kind": "replay",
    "reason": "store_timeout",
    "rule_id": "replay/store_timeout"
  },
  {
    "kind": "replay",
    "reason": "store_unavailable",
    "rule_id": "replay/store_unavailable"
  },
  {
    "kind": "adapter",
    "reason": "already_verified",
    "rule_id": "adapter/already_verified"
  },
  {
    "kind": "adapter",
    "reason": "body_unavailable",
    "rule_id": "adapter/body_unavailable"
  },
  {
    "kind": "adapter",
    "reason": "cross_origin_redirect",
    "rule_id": "adapter/cross_origin_redirect"
  },
  {
    "kind": "adapter",
    "reason": "digest_conflict",
    "rule_id": "adapter/digest_conflict"
  },
  {
    "kind": "adapter",
    "reason": "invalid_options",
    "rule_id": "adapter/invalid_options"
  },
  {
    "kind": "adapter",
    "reason": "invalid_request",
    "rule_id": "adapter/invalid_request"
  },
  {
    "kind": "adapter",
    "reason": "limit",
    "rule_id": "adapter/limit"
  },
  {
    "kind": "adapter",
    "reason": "not_captured",
    "rule_id": "adapter/not_captured"
  },
  {
    "kind": "adapter",
    "reason": "not_final_step",
    "rule_id": "adapter/not_final_step"
  },
  {
    "kind": "adapter",
    "reason": "parser_order",
    "rule_id": "adapter/parser_order"
  },
  {
    "kind": "adapter",
    "reason": "request_rejected",
    "rule_id": "adapter/request_rejected"
  },
  {
    "kind": "adapter",
    "reason": "response_rejected",
    "rule_id": "adapter/response_rejected"
  },
  {
    "kind": "adapter",
    "reason": "signing_failed",
    "rule_id": "adapter/signing_failed"
  },
  {
    "kind": "adapter",
    "reason": "unsupported_component",
    "rule_id": "adapter/unsupported_component"
  },
  {
    "kind": "adapter",
    "reason": "unsupported_delivery",
    "rule_id": "adapter/unsupported_delivery"
  },
  {
    "kind": "adapter",
    "reason": "untrusted_proxy",
    "rule_id": "adapter/untrusted_proxy"
  }
] as const;

const retryableRules = {
  "core": {
    "actor_unbound": {
      "kind": "constant",
      "value": false
    },
    "agent_unresolved": {
      "kind": "constant",
      "value": false
    },
    "algorithm_mismatch": {
      "kind": "constant",
      "value": false
    },
    "algorithm_not_permitted": {
      "kind": "constant",
      "value": false
    },
    "ambiguous_key_identity": {
      "kind": "constant",
      "value": false
    },
    "binding_unsatisfied": {
      "kind": "constant",
      "value": false
    },
    "body_unavailable": {
      "kind": "constant",
      "value": false
    },
    "commitment_failed": {
      "kind": "constant",
      "value": false
    },
    "created_in_future": {
      "kind": "constant",
      "value": false
    },
    "digest_mismatch": {
      "kind": "constant",
      "value": false
    },
    "digest_not_covered": {
      "kind": "constant",
      "value": false
    },
    "digest_unsupported": {
      "kind": "constant",
      "value": false
    },
    "duplicate_label": {
      "kind": "constant",
      "value": false
    },
    "duplicate_parameter": {
      "kind": "constant",
      "value": false
    },
    "expired": {
      "kind": "constant",
      "value": false
    },
    "inapplicable_component": {
      "kind": "constant",
      "value": false
    },
    "invalid_accept_signature": {
      "kind": "constant",
      "value": false
    },
    "invalid_binding": {
      "kind": "constant",
      "value": false
    },
    "invalid_clock": {
      "kind": "constant",
      "value": false
    },
    "invalid_keyid": {
      "kind": "constant",
      "value": false
    },
    "invalid_message": {
      "kind": "constant",
      "value": false
    },
    "invalid_options": {
      "kind": "constant",
      "value": false
    },
    "invalid_policy": {
      "kind": "constant",
      "value": false
    },
    "invalid_profile": {
      "kind": "constant",
      "value": false
    },
    "invalid_quorum": {
      "kind": "constant",
      "value": false
    },
    "invalid_request": {
      "kind": "constant",
      "value": false
    },
    "invalid_signature": {
      "kind": "constant",
      "value": false
    },
    "invalid_signature_agent": {
      "kind": "constant",
      "value": false
    },
    "invalid_signature_field": {
      "kind": "constant",
      "value": false
    },
    "invalid_signature_input": {
      "kind": "constant",
      "value": false
    },
    "invalid_verification": {
      "kind": "constant",
      "value": false
    },
    "key_resolver_failed": {
      "kind": "constant",
      "value": false
    },
    "label_in_use": {
      "kind": "constant",
      "value": false
    },
    "label_mismatch": {
      "kind": "constant",
      "value": false
    },
    "lifetime_exceeded": {
      "kind": "constant",
      "value": false
    },
    "limit": {
      "kind": "constant",
      "value": false
    },
    "missing_created": {
      "kind": "constant",
      "value": false
    },
    "missing_expires": {
      "kind": "constant",
      "value": false
    },
    "missing_replay_identifier": {
      "kind": "constant",
      "value": false
    },
    "missing_required_component": {
      "kind": "constant",
      "value": false
    },
    "missing_signature": {
      "kind": "constant",
      "value": false
    },
    "missing_signature_input": {
      "kind": "constant",
      "value": false
    },
    "negotiation_unfulfillable": {
      "kind": "constant",
      "value": false
    },
    "negotiation_unfulfilled": {
      "kind": "constant",
      "value": false
    },
    "nested_coverage_incomplete": {
      "kind": "constant",
      "value": false
    },
    "no_web_bot_auth_signature": {
      "kind": "constant",
      "value": false
    },
    "nonqualifying_signature": {
      "kind": "constant",
      "value": false
    },
    "quorum_not_met": {
      "kind": "constant",
      "value": false
    },
    "replayed": {
      "kind": "constant",
      "value": false
    },
    "retention_exceeded": {
      "kind": "constant",
      "value": false
    },
    "signature_base_failed": {
      "kind": "constant",
      "value": false
    },
    "signer_algorithm_mismatch": {
      "kind": "constant",
      "value": false
    },
    "signer_failed": {
      "kind": "constant",
      "value": false
    },
    "signing_failed": {
      "kind": "constant",
      "value": false
    },
    "store_failed": {
      "kind": "constant",
      "value": false
    },
    "store_timeout": {
      "kind": "constant",
      "value": false
    },
    "store_unavailable": {
      "kind": "constant",
      "value": false
    },
    "tenant_unbound": {
      "kind": "constant",
      "value": false
    },
    "test_key_rejected": {
      "kind": "constant",
      "value": false
    },
    "too_old": {
      "kind": "constant",
      "value": false
    },
    "unattributed": {
      "kind": "constant",
      "value": false
    },
    "unexpected_component": {
      "kind": "constant",
      "value": false
    },
    "unexpected_signature": {
      "kind": "constant",
      "value": false
    },
    "unknown_key": {
      "kind": "constant",
      "value": false
    },
    "unknown_label": {
      "kind": "constant",
      "value": false
    },
    "unsupported_component": {
      "kind": "constant",
      "value": false
    },
    "verifier_failed": {
      "kind": "constant",
      "value": false
    }
  },
  "message": {
    "invalid_body": {
      "kind": "constant",
      "value": false
    },
    "invalid_field": {
      "kind": "constant",
      "value": false
    },
    "invalid_message": {
      "kind": "constant",
      "value": false
    },
    "invalid_transport": {
      "kind": "constant",
      "value": false
    }
  },
  "structured_fields": {
    "duplicate_key": {
      "kind": "constant",
      "value": false
    },
    "duplicate_parameter": {
      "kind": "constant",
      "value": false
    },
    "invalid_field": {
      "kind": "constant",
      "value": false
    },
    "invalid_limits": {
      "kind": "constant",
      "value": false
    },
    "invalid_message": {
      "kind": "constant",
      "value": false
    },
    "invalid_schema": {
      "kind": "constant",
      "value": false
    },
    "invalid_value": {
      "kind": "constant",
      "value": false
    },
    "limit": {
      "kind": "constant",
      "value": false
    },
    "missing_field": {
      "kind": "constant",
      "value": false
    },
    "revision_type": {
      "kind": "constant",
      "value": false
    },
    "schema_type": {
      "kind": "constant",
      "value": false
    },
    "syntax": {
      "kind": "constant",
      "value": false
    },
    "unavailable_section": {
      "kind": "constant",
      "value": false
    }
  },
  "signature_base": {
    "ambiguous_query_parameter": {
      "kind": "constant",
      "value": false
    },
    "duplicate_component": {
      "kind": "constant",
      "value": false
    },
    "incompatible_parameters": {
      "kind": "constant",
      "value": false
    },
    "invalid_component": {
      "kind": "constant",
      "value": false
    },
    "invalid_component_parameters": {
      "kind": "constant",
      "value": false
    },
    "invalid_field_schema": {
      "kind": "constant",
      "value": false
    },
    "invalid_message": {
      "kind": "constant",
      "value": false
    },
    "invalid_options": {
      "kind": "constant",
      "value": false
    },
    "invalid_query_encoding": {
      "kind": "constant",
      "value": false
    },
    "invalid_signature_parameters": {
      "kind": "constant",
      "value": false
    },
    "invalid_structured_field": {
      "kind": "constant",
      "value": false
    },
    "limit": {
      "kind": "constant",
      "value": false
    },
    "missing_dictionary_key": {
      "kind": "constant",
      "value": false
    },
    "missing_field": {
      "kind": "constant",
      "value": false
    },
    "missing_query_parameter": {
      "kind": "constant",
      "value": false
    },
    "missing_request_context": {
      "kind": "constant",
      "value": false
    },
    "non_ascii": {
      "kind": "constant",
      "value": false
    },
    "noncanonical_query_name": {
      "kind": "constant",
      "value": false
    },
    "unavailable_origin": {
      "kind": "constant",
      "value": false
    },
    "unavailable_trailers": {
      "kind": "constant",
      "value": false
    },
    "unknown_component": {
      "kind": "constant",
      "value": false
    },
    "unknown_field_schema": {
      "kind": "constant",
      "value": false
    },
    "wrong_message_kind": {
      "kind": "constant",
      "value": false
    }
  },
  "digest": {
    "body_unavailable": {
      "kind": "constant",
      "value": false
    },
    "conflicting_digest": {
      "kind": "constant",
      "value": false
    },
    "invalid_body": {
      "kind": "constant",
      "value": false
    },
    "invalid_chunk": {
      "kind": "constant",
      "value": false
    },
    "invalid_digest_length": {
      "kind": "constant",
      "value": false
    },
    "invalid_field": {
      "kind": "constant",
      "value": false
    },
    "invalid_kind": {
      "kind": "constant",
      "value": false
    },
    "invalid_message": {
      "kind": "constant",
      "value": false
    },
    "invalid_options": {
      "kind": "constant",
      "value": false
    },
    "invalid_preference": {
      "kind": "constant",
      "value": false
    },
    "invalid_state": {
      "kind": "constant",
      "value": false
    },
    "limit": {
      "kind": "constant",
      "value": false
    },
    "mismatch": {
      "kind": "constant",
      "value": false
    },
    "representation_required": {
      "kind": "constant",
      "value": false
    },
    "uncomputed_algorithm": {
      "kind": "constant",
      "value": false
    },
    "unsupported_algorithm": {
      "kind": "constant",
      "value": false
    }
  },
  "crypto": {
    "invalid_data": {
      "kind": "constant",
      "value": false
    },
    "invalid_key": {
      "kind": "constant",
      "value": false
    },
    "invalid_options": {
      "kind": "constant",
      "value": false
    },
    "invalid_signature": {
      "kind": "constant",
      "value": false
    },
    "key_mismatch": {
      "kind": "constant",
      "value": false
    },
    "unsupported_algorithm": {
      "kind": "constant",
      "value": false
    },
    "unsupported_format": {
      "kind": "constant",
      "value": false
    }
  },
  "custody": {
    "custodian_failure": {
      "kind": "constant",
      "value": false
    },
    "custodian_protocol": {
      "kind": "constant",
      "value": false
    },
    "custodian_rejected": {
      "kind": "constant",
      "value": false
    },
    "custodian_unavailable": {
      "kind": "constant",
      "value": true
    },
    "deadline_exceeded": {
      "kind": "constant",
      "value": true
    },
    "decryption_failed": {
      "kind": "constant",
      "value": false
    },
    "invalid_data": {
      "kind": "constant",
      "value": false
    },
    "invalid_handle": {
      "kind": "constant",
      "value": false
    },
    "invalid_key": {
      "kind": "constant",
      "value": false
    },
    "invalid_options": {
      "kind": "constant",
      "value": false
    },
    "invalid_signature": {
      "kind": "constant",
      "value": false
    },
    "invalid_signing_output": {
      "kind": "constant",
      "value": false
    },
    "key_mismatch": {
      "kind": "constant",
      "value": false
    },
    "key_not_found": {
      "kind": "constant",
      "value": false
    },
    "limit": {
      "kind": "constant",
      "value": false
    },
    "no_public_key": {
      "kind": "constant",
      "value": false
    },
    "unsupported_algorithm": {
      "kind": "constant",
      "value": false
    },
    "unsupported_format": {
      "kind": "constant",
      "value": false
    },
    "unsupported_operation": {
      "kind": "constant",
      "value": false
    }
  },
  "discovery": {
    "address_denied": {
      "kind": "constant",
      "value": false
    },
    "ambiguous_key_source": {
      "kind": "constant",
      "value": false
    },
    "cache_overloaded": {
      "kind": "constant",
      "value": true
    },
    "client_id_mismatch": {
      "kind": "constant",
      "value": false
    },
    "connect_failed": {
      "kind": "constant",
      "value": true
    },
    "deadline_exceeded": {
      "kind": "constant",
      "value": true
    },
    "directory_signature_invalid": {
      "kind": "constant",
      "value": false
    },
    "directory_unsigned": {
      "kind": "constant",
      "value": false
    },
    "invalid_key_set": {
      "kind": "constant",
      "value": false
    },
    "invalid_options": {
      "kind": "constant",
      "value": false
    },
    "invalid_response": {
      "kind": "constant",
      "value": false
    },
    "invalid_source": {
      "kind": "constant",
      "value": false
    },
    "limit": {
      "kind": "constant",
      "value": false
    },
    "redirect_denied": {
      "kind": "constant",
      "value": false
    },
    "redirect_limit": {
      "kind": "constant",
      "value": false
    },
    "resolution_failed": {
      "kind": "constant",
      "value": false
    },
    "revoked_key": {
      "kind": "constant",
      "value": false
    },
    "source_unavailable": {
      "kind": "constant",
      "value": true
    },
    "tls_failed": {
      "kind": "constant",
      "value": false
    },
    "transport_unavailable": {
      "kind": "constant",
      "value": false
    },
    "unexpected_media_type": {
      "kind": "constant",
      "value": false
    },
    "unexpected_status": {
      "kind": "status-derived (5xx)",
      "minimum": 500,
      "maximum": 599,
      "path": "lib/request_seal/discovery.ex",
      "line": 301
    },
    "unknown_key": {
      "kind": "constant",
      "value": false
    }
  },
  "jose": {
    "algorithm_mismatch": {
      "kind": "constant",
      "value": false
    },
    "algorithm_not_permitted": {
      "kind": "constant",
      "value": false
    },
    "compression_unsupported": {
      "kind": "constant",
      "value": false
    },
    "content_type_mismatch": {
      "kind": "constant",
      "value": false
    },
    "deadline_exceeded": {
      "kind": "constant",
      "value": true
    },
    "decryption_failed": {
      "kind": "constant",
      "value": false
    },
    "detached_payload": {
      "kind": "constant",
      "value": false
    },
    "duplicate_member": {
      "kind": "constant",
      "value": false
    },
    "entropy_failure": {
      "kind": "constant",
      "value": false
    },
    "invalid_base64": {
      "kind": "constant",
      "value": false
    },
    "invalid_header": {
      "kind": "constant",
      "value": false
    },
    "invalid_iv": {
      "kind": "constant",
      "value": false
    },
    "invalid_options": {
      "kind": "constant",
      "value": false
    },
    "invalid_policy": {
      "kind": "constant",
      "value": false
    },
    "invalid_serialization": {
      "kind": "constant",
      "value": false
    },
    "invalid_signature": {
      "kind": "constant",
      "value": false
    },
    "invalid_tag": {
      "kind": "constant",
      "value": false
    },
    "key_resolver_failed": {
      "kind": "constant",
      "value": false
    },
    "limit": {
      "kind": "constant",
      "value": false
    },
    "nesting_depth": {
      "kind": "constant",
      "value": false
    },
    "signer_failed": {
      "kind": "constant",
      "value": false
    },
    "unknown_key": {
      "kind": "constant",
      "value": false
    },
    "unsupported_critical_header": {
      "kind": "constant",
      "value": false
    },
    "unsupported_header": {
      "kind": "constant",
      "value": false
    },
    "unsupported_serialization": {
      "kind": "constant",
      "value": false
    }
  },
  "replay": {
    "invalid_claim": {
      "kind": "constant",
      "value": false
    },
    "invalid_options": {
      "kind": "constant",
      "value": false
    },
    "invalid_store": {
      "kind": "constant",
      "value": false
    },
    "store_failed": {
      "kind": "constant",
      "value": false
    },
    "store_full": {
      "kind": "constant",
      "value": false
    },
    "store_timeout": {
      "kind": "constant",
      "value": false
    },
    "store_unavailable": {
      "kind": "constant",
      "value": false
    }
  },
  "adapter": {
    "already_verified": {
      "kind": "constant",
      "value": false
    },
    "body_unavailable": {
      "kind": "constant",
      "value": false
    },
    "cross_origin_redirect": {
      "kind": "constant",
      "value": false
    },
    "digest_conflict": {
      "kind": "constant",
      "value": false
    },
    "invalid_options": {
      "kind": "constant",
      "value": false
    },
    "invalid_request": {
      "kind": "constant",
      "value": false
    },
    "limit": {
      "kind": "constant",
      "value": false
    },
    "not_captured": {
      "kind": "constant",
      "value": false
    },
    "not_final_step": {
      "kind": "constant",
      "value": false
    },
    "parser_order": {
      "kind": "constant",
      "value": false
    },
    "request_rejected": {
      "kind": "constant",
      "value": false
    },
    "response_rejected": {
      "kind": "constant",
      "value": false
    },
    "signing_failed": {
      "kind": "constant",
      "value": false
    },
    "unsupported_component": {
      "kind": "constant",
      "value": false
    },
    "unsupported_delivery": {
      "kind": "constant",
      "value": false
    },
    "untrusted_proxy": {
      "kind": "constant",
      "value": false
    }
  }
} as const;
export const ERROR_RETRYABLE = Object.freeze(Object.fromEntries(Object.entries(retryableRules).map(([kind, rules]) => [kind, Object.freeze(Object.fromEntries(Object.entries(rules).map(([reason, rule]) => [reason, Object.freeze(rule)])))]))) as typeof retryableRules;

export const ERROR_PARITY = Object.freeze(entries.map(entry => Object.freeze(entry)));
export type ParityEntry = typeof ERROR_PARITY[number];
export type ErrorKind = ParityEntry["kind"];
export type Reason<K extends ErrorKind> = Extract<ParityEntry, { kind: K }>["reason"];
export type Layer<K extends "core" | "jose"> = Extract<ParityEntry, { kind: K }>["layer"];
const rules = new Set(ERROR_PARITY.map(e => e.rule_id as string));
// A frozen Set still exposes mutation methods; the facade keeps the backing Set private.
export const RULE_IDS: ReadonlySet<string> = Object.freeze({
  get size() { return rules.size; },
  has: (value: string) => rules.has(value),
  keys: () => rules.keys(), values: () => rules.values(), entries: () => rules.entries(),
  [Symbol.iterator]: () => rules[Symbol.iterator](),
  forEach(callback: (value: string, key: string, set: ReadonlySet<string>) => void, thisArg?: unknown) {
    rules.forEach(value => callback.call(thisArg, value, value, RULE_IDS));
  }
});
