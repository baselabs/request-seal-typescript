**Status:** maintained · **Kind:** reference · **Updated:** October 14, 2026 · **Governed by:** the error vocabulary in `src/errors/parity.ts` and the code that returns each reason · **Review when:** a reason is added, removed, or starts to be returned on a new path

# Error reasons

Every failure is a `Result` whose `error` has a stable `kind` and `reason`, and for `core` and `jose` a `layer`. This page says what each reason means and what to do about it. Branch on these values, never on message text. The [error vocabulary](error-parity.md) is the generated list with its pin, and the [README](../../README.md#reason-to-http-status-recommendation) recommends an HTTP status for each. A test checks that this page lists every reason in the vocabulary.

Adapter errors can carry the underlying error in `error.source`; the [adapter section](#adapter) says when. A few reasons are part of the vocabulary shared with RequestSeal for Elixir and are never returned by this package; they are marked "Not returned here."

## core

Returned by `sign`, `verify`, `verifyQuorum`, Web Bot Auth, Accept-Signature, and policy construction. `layer` says which stage failed.

| Reason | Meaning | What to do |
| --- | --- | --- |
| `core/binding.actor_unbound` | Not returned here. | None. |
| `core/binding.invalid_binding` | Not returned here. | None. |
| `core/binding.invalid_verification` | A value passed as a Verification is not one this library produced. | Pass the Verification from `verify` unchanged. |
| `core/binding.tenant_unbound` | Not returned here. | None. |
| `core/binding.unattributed` | Not returned here. | None. |
| `core/content.body_unavailable` | A required digest check, or digest generation while signing, needs body bytes the message does not hold. | Retain the body, pass a `digestState` or `representation`, or stop requiring content on that path. |
| `core/content.digest_mismatch` | The recomputed digest differs from the signed one: the body changed. | Reject the request. |
| `core/content.digest_not_covered` | The policy requires a digest field that the signature does not cover. | The sender must cover `content-digest` (or `repr-digest`). |
| `core/content.digest_unsupported` | The digest field is missing or malformed, carries an algorithm your policy does not accept, or the hasher failed. | Accept the sender's algorithm, or have the sender use one you accept. |
| `core/crypto.invalid_signature` | The signature does not verify with the resolved key. | Reject the request. |
| `core/crypto.signature_base_failed` | An exact-input spec could not build its signature base; `detail` names the base reason. | Fix the `signatureInput` or the message. |
| `core/crypto.signer_failed` | A signer function threw, returned an error, or returned something other than 1 to 1,024 signature bytes. | Fix the signer function. |
| `core/crypto.signing_failed` | A KeyHandle failed to sign; `source` holds the custody error. | Read `source`; retry only if `source.retryable`. |
| `core/crypto.verifier_failed` | A verification callback threw or returned a malformed result. | Fix the callback to return `ok(true)`, `ok(false)`, or an error. |
| `core/fields.duplicate_label` | `Signature-Input` or `Signature` repeats a label. | Reject the request. |
| `core/fields.duplicate_parameter` | A signature or Accept-Signature entry repeats a parameter. | Reject the request. |
| `core/fields.invalid_signature_agent` | The `Signature-Agent` field breaks the Web Bot Auth rules; `detail` says how. | Reject the request. |
| `core/fields.invalid_signature_field` | The `Signature` field, or a signature passed to `Profile.verifyLabel`, is malformed. | Reject the request, or pass the parsed signature unchanged. |
| `core/fields.invalid_signature_input` | `Signature-Input` or a spec's `signatureInput` is malformed. | Reject the request, or fix the spec. |
| `core/fields.label_in_use` | Signing would reuse a label already on the message. | Choose another label. |
| `core/fields.label_mismatch` | `Signature-Input` and `Signature` carry different labels. | Reject the request. |
| `core/fields.missing_signature` | The message has no `Signature` field. | Ask the sender to sign. |
| `core/fields.missing_signature_input` | The message has no `Signature-Input` field. | Ask the sender to sign. |
| `core/fields.no_web_bot_auth_signature` | No signature carries the `web-bot-auth` tag. | Treat the request as unsigned. |
| `core/fields.unknown_label` | The label you asked for is not on the message. | Ask for the label the sender used. |
| `core/freshness.created_in_future` | `created` is later than your clock plus `skew`. | Reject; check the sender's clock. |
| `core/freshness.expired` | `expires` has passed. | The sender signs again. |
| `core/freshness.invalid_clock` | Your clock callback returned something other than integer Unix seconds in range. | Fix the clock. |
| `core/freshness.lifetime_exceeded` | `expires` minus `created` exceeds the Web Bot Auth `maxLifetime`. | Reject, or raise `maxLifetime`. |
| `core/freshness.missing_created` | The signature has no `created`, which a policy with `maxAge` needs. | The sender adds `created`. |
| `core/freshness.missing_expires` | The signature has no `expires`, and your policy requires it. | The sender adds `expires`. |
| `core/freshness.too_old` | `created` is older than `maxAge` plus `skew`. | The sender signs again. |
| `core/input.algorithm_mismatch` | A spec's `signatureInput` names an `alg` other than the spec's algorithm. | Make them agree. |
| `core/input.invalid_message` | The value is not a valid branded Message. | Build it with `Message.request`, `Message.response`, or `Message.create`. |
| `core/input.invalid_options` | An options object has an unknown key or a bad value. | Fix the options. |
| `core/input.invalid_policy` | A policy is missing a choice, has an unknown key, or has a bad value. | Fix the policy. |
| `core/input.invalid_profile` | A profile stamp is malformed or reserved, or generic `verify` received `profile` or `principal`. | Fix the stamp or options. |
| `core/input.invalid_quorum` | A quorum definition is malformed. | Fix the quorum. |
| `core/input.invalid_request` | Signing covers `content-length`, and the message's `Content-Length` disagrees with its body. | Fix the message. |
| `core/input.limit` | An input exceeds a size, count, or depth bound. | Reject, or send less. |
| `core/input.signer_algorithm_mismatch` | An exact-input spec's KeyHandle is bound to another algorithm. | Use a handle for the spec's algorithm. |
| `core/internal.internal` | An unexpected fault inside the library; `detail` names the bounded exception class. Not marked retryable. | Report it; the same input is not retried blindly. |
| `core/input.unsupported_component` | Signing would cover a component it refuses (`host`, `;tr`, or `;req` on a request), or a generated base cannot be built. | Cover `@authority` instead of `host`, or fix the components. |
| `core/key.agent_unresolved` | Web Bot Auth trust could not connect the signature to a key; `detail` says why. | See [Web Bot Auth errors](../guides/web-bot-auth.md#errors-you-will-see). |
| `core/key.key_resolver_failed` | Your key resolver threw, returned an error, or returned a malformed entry. | Fix the resolver; return `ok(null)` for unknown keys. |
| `core/key.unknown_key` | The resolver returned `ok(null)`. | Reject the request. |
| `core/negotiation.inapplicable_component` | An Accept-Signature request names a component that cannot apply to its target. | Reject the Accept-Signature field. |
| `core/negotiation.invalid_accept_signature` | An Accept-Signature value is malformed. | Reject the field or fix the option. |
| `core/negotiation.negotiation_unfulfillable` | Fulfillment could not produce a requested signature: the chooser refused or the signer failed. | Check the chooser and signer. |
| `core/negotiation.negotiation_unfulfilled` | In `verifyQuorum` with `acceptSignature`, the qualifying signatures do not carry what a request asked for. | The sender signs as requested. |
| `core/policy.algorithm_mismatch` | The sender's `alg` parameter differs from the resolved key's algorithm. | Reject the request. |
| `core/policy.algorithm_not_permitted` | The algorithm is not in your policy's `algorithms`. | Reject, or accept the algorithm. |
| `core/policy.invalid_keyid` | A Web Bot Auth `keyid` is not an RFC 7638 thumbprint. | Reject the request. |
| `core/policy.missing_required_component` | The signature does not cover a component your policy requires. | The sender covers it. |
| `core/policy.nested_coverage_incomplete` | An outer Web Bot Auth signature does not cover the inner signature it vouches for. | Reject the request. |
| `core/policy.test_key_rejected` | The key is a published example key. | Reject; allow only with `testKeys: "allow"` in tests. |
| `core/policy.unexpected_component` | The signature covers a component that `extraComponents: "reject"` refuses. | Reject, or allow the component. |
| `core/policy.unexpected_signature` | With `untagged: "reject"`, a signature lacks the `web-bot-auth` tag. | Reject, or use `untagged: "ignore"`. |
| `core/quorum.ambiguous_key_identity` | When counting keys, a required slot matched only signatures with no known key identity. | Supply key identities through the resolver. |
| `core/quorum.deadline` | The caller's wall-clock deadline exhausted the assignment search before a satisfying assignment completed. Retryable. | Retry with a later deadline or under less load. |
| `core/quorum.binding_unsatisfied` | A nested or same-parameter binding failed. | Reject the request. |
| `core/quorum.nonqualifying_signature` | With `invalid: "reject"`, a signature failed its slot; `detail` is that slot's reason. | Reject the request. |
| `core/quorum.quorum_not_met` | Too few qualifying signatures for the mode. | Reject the request. |
| `core/quorum.unexpected_signature` | With `unexpected: "reject"`, a signature matched no slot. | Reject, or use `unexpected: "ignore"`. |
| `core/replay.commitment_failed` | Your commitment threw or returned anything but 1 to 256 bytes. | Fix the commitment. |
| `core/replay.missing_replay_identifier` | Replay protection is required and the signature has no nonce. | The sender adds a nonce. |
| `core/replay.replayed` | The signature was already used. | Reject the request. |
| `core/replay.retention_exceeded` | The claim would have to be kept past the largest supported time (253,402,300,799), during verification or from `Replay.retainUntil`. | Reject; the signature's window is too long. |
| `core/replay.store_failed` | The replay store failed or is full; the claim may or may not have landed. | Answer with a transient error; the sender signs again. |
| `core/replay.store_timeout` | The replay claim ran out of time; it may have committed. | Answer with a transient error; the sender signs again. |
| `core/replay.store_unavailable` | The replay store could not be reached. | Answer with a transient error. |

## message

Returned by `Message`, `FieldOccurrence`, `Body`, and `TransportFacts` construction.

| Reason | Meaning | What to do |
| --- | --- | --- |
| `message/invalid_body` | A body value is malformed. | Fix the body. |
| `message/invalid_field` | A field name or value is not valid HTTP. | Fix the field. |
| `message/invalid_message` | A message attribute is malformed, such as a non-HTTP(S) URL, a fragment, or a bad status. | Fix the message. |
| `message/invalid_transport` | Transport facts are malformed. | Fix the transport facts. |

## structured_fields

Returned by Structured Fields parsing and serialization.

| Reason | Meaning | What to do |
| --- | --- | --- |
| `structured_fields/duplicate_key` | A dictionary repeats a key under `uniqueKeys`. | Reject the field. |
| `structured_fields/duplicate_parameter` | A parameter repeats under `uniqueParameters`. | Reject the field. |
| `structured_fields/invalid_field` | A field occurrence passed to `parseField` is malformed. | Fix the input. |
| `structured_fields/invalid_limits` | Parse options or limits are malformed. | Fix the options. |
| `structured_fields/invalid_message` | `parseField` did not receive a branded Message. | Pass a Message. |
| `structured_fields/invalid_schema` | A schema is malformed. | Fix the schema with `createSchema`. |
| `structured_fields/invalid_value` | A value to serialize is not a valid Structured Fields tree. | Fix the value. |
| `structured_fields/limit` | Input exceeds a size, count, or depth bound. | Reject the field. |
| `structured_fields/missing_field` | The requested field is absent. | Treat the field as missing. |
| `structured_fields/revision_type` | A value uses a type the selected RFC revision does not allow. | Choose the right revision or reject. |
| `structured_fields/schema_type` | A value has a type the schema does not allow. | Reject the field or widen the schema. |
| `structured_fields/syntax` | The text is not valid Structured Fields, including a byte sequence with nonzero base64 padding bits. Missing `=` padding is accepted. | Reject the field. |
| `structured_fields/unavailable_section` | The requested section (such as pending trailers) is not available. | Read the section once it is complete. |

## signature_base

Returned by `SignatureBase.build`, and as `detail` of core errors from signing and verification.

| Reason | Meaning | What to do |
| --- | --- | --- |
| `signature_base/ambiguous_query_parameter` | `@query-param` names a parameter that appears more than once. | Do not cover that parameter. |
| `signature_base/duplicate_component` | The component list repeats a component. | Remove the duplicate. |
| `signature_base/incompatible_parameters` | A component combines `bs` with `sf` or `key`. | Use one form. |
| `signature_base/invalid_component` | A component identifier is malformed. | Fix the component list. |
| `signature_base/invalid_component_parameters` | A component carries an unknown or malformed parameter, or `@query-param` lacks `name`. | Fix the parameters. |
| `signature_base/invalid_field_schema` | A field schema is malformed. | Fix `fieldSchemas`. |
| `signature_base/invalid_message` | The value is not a branded Message. | Pass a Message. |
| `signature_base/invalid_options` | Build options are malformed. | Fix the options. |
| `signature_base/invalid_query_encoding` | The query cannot be decoded as form data. | Do not cover `@query-param` for that request. |
| `signature_base/invalid_signature_parameters` | The signature parameters are malformed. | Fix the parameters. |
| `signature_base/invalid_structured_field` | A field covered with `sf` or `key` is not valid under its schema. | Reject, or fix the schema. |
| `signature_base/limit` | The base would exceed a size or count bound. | Cover less. |
| `signature_base/missing_dictionary_key` | A `key` parameter names a member the dictionary lacks. | Reject the request. |
| `signature_base/missing_field` | A covered field is absent. | Reject, or cover only present fields. |
| `signature_base/missing_query_parameter` | `@query-param` names a parameter the query lacks. | Reject the request. |
| `signature_base/missing_request_context` | A `;req` component has no related request. | Link the request with `Message.response(..., { request })`. |
| `signature_base/non_ascii` | A covered value contains bytes outside visible ASCII. | Reject, or cover with `bs`. |
| `signature_base/noncanonical_query_name` | A `@query-param` name is not in canonical encoded form. | Use the canonical encoding. |
| `signature_base/unavailable_origin` | A derived component needs a scheme and authority the message lacks. | Build the message with an absolute URL or set them. |
| `signature_base/unavailable_trailers` | A trailer component was requested while trailers are pending. | Verify after the trailers arrive. |
| `signature_base/unknown_component` | A derived component name is not defined by RFC 9421. | Fix the component list. |
| `signature_base/unknown_field_schema` | An `sf` or `key` component has no schema for a field that needs one. | Supply it in `fieldSchemas`. |
| `signature_base/wrong_message_kind` | A component does not apply to this kind of message, such as `@status` on a request. | Fix the component list. |

## digest

Returned by `digest`, `DigestState`, `checkDigest`, and the digest field helpers.

| Reason | Meaning | What to do |
| --- | --- | --- |
| `digest/body_unavailable` | The body bytes are not retained. | Retain the body or stream through `DigestState`. |
| `digest/conflicting_digest` | The digest field repeats an algorithm. | Reject the field. |
| `digest/invalid_body` | A body value is malformed. | Fix the body. |
| `digest/invalid_chunk` | An update received something other than bytes. | Pass `Uint8Array` chunks. |
| `digest/invalid_digest_length` | A digest value has the wrong length for its algorithm. | Reject the field. |
| `digest/invalid_field` | The digest field is not a valid dictionary of byte sequences. | Reject the field. |
| `digest/invalid_kind` | The kind is not `content` or `representation`. | Use one of those. |
| `digest/invalid_message` | The value is not a branded Message. | Pass a Message. |
| `digest/invalid_options` | Options, such as `maxBytes`, are malformed. | Fix the options. |
| `digest/invalid_preference` | Not returned here. | None. |
| `digest/invalid_state` | A `DigestState` was misused, such as an update after finish or overlapping calls, or the hasher failed its self-test. | Use one state per body, sequentially. |
| `digest/limit` | Input exceeds the work bound. | Raise `maxBytes` for a stream, or reject. |
| `digest/mismatch` | The recomputed digest differs from the field. | Reject the message. |
| `digest/representation_required` | A representation check was asked for without the representation. | Pass `representation`. |
| `digest/uncomputed_algorithm` | The field lists an algorithm the state did not compute. | Create the state with that algorithm. |
| `digest/unsupported_algorithm` | The algorithm is not SHA-256 or SHA-512. | Use one of those. |

## crypto

Returned by `Crypto.sign`, `Crypto.verify`, and `publicKey.verify`.

| Reason | Meaning | What to do |
| --- | --- | --- |
| `crypto/invalid_data` | The data is not bytes or exceeds `maxBytes`. | Pass bytes within the bound. |
| `crypto/invalid_key` | The key cannot be used for the operation. | Use a valid key for the algorithm. |
| `crypto/invalid_options` | The trailing options are malformed. | Fix the options. |
| `crypto/invalid_signature` | The signature does not verify. | Reject. |
| `crypto/key_mismatch` | The key does not fit the algorithm. | Use a key of the right type. |
| `crypto/unsupported_algorithm` | The algorithm is not supported. | Use a supported algorithm. |
| `crypto/unsupported_format` | The key format is not supported. | Import a supported format. |

## custody

Returned by `Custody.local`, KeyHandle methods, `createKeyHandle`, `createSshAgent`, and deadlines.

| Reason | Meaning | What to do |
| --- | --- | --- |
| `custody/custodian_failure` | Custodian code threw or returned a malformed result. | Fix the custodian. |
| `custody/custodian_protocol` | The custodian, such as an ssh-agent, sent a malformed or incomplete reply. | Check the agent. |
| `custody/custodian_rejected` | The custodian refused, such as an ssh-agent that does not hold the key. | Load the key into the agent. |
| `custody/custodian_unavailable` | The custodian could not be reached. Retryable. | Retry later. |
| `custody/deadline_exceeded` | The Context deadline passed or was canceled. Retryable. | Retry with a fresh deadline. |
| `custody/decryption_failed` | Decryption failed. | Reject. |
| `custody/invalid_data` | The data is not bytes or exceeds `maxBytes`. | Pass bytes within the bound. |
| `custody/invalid_handle` | `createKeyHandle` received a malformed custodian or capability list. | Fix the custodian. |
| `custody/invalid_key` | The key material is invalid, or failed its health check. | Use valid key material. |
| `custody/invalid_options` | Options are malformed. | Fix the options. |
| `custody/invalid_signature` | A custody verification failed. | Reject. |
| `custody/invalid_signing_output` | A handle returned empty, non-byte, or oversized signature output. | Fix the custodian. |
| `custody/key_mismatch` | The key does not fit the algorithm. | Use a key of the right type. |
| `custody/key_not_found` | The handle was released, or the agent no longer holds the key. | Create a new handle. |
| `custody/limit` | Input exceeds a bound. | Send less. |
| `custody/no_public_key` | The handle has no public key, as for HMAC. | Do not ask an HMAC handle for a public key. |
| `custody/unsupported_algorithm` | The algorithm is not supported by this custody. | Use a supported algorithm. |
| `custody/unsupported_format` | The key format is not supported. | Import a supported format. |
| `custody/unsupported_operation` | The handle lacks the capability, such as `sign`. | Use a handle with that capability. |

## discovery

Returned by discovery sources, snapshots, key sets, caches, and the Node transport. `retryable` marks transient failures.

| Reason | Meaning | What to do |
| --- | --- | --- |
| `discovery/address_denied` | The host resolves to a private, loopback, or reserved address not in `permittedAddresses`. | Do not fetch it, or permit the exact address. |
| `discovery/ambiguous_key_source` | A client metadata document carries both `jwks` and `jwks_uri`. | Reject the document. |
| `discovery/cache_overloaded` | The cache is at its source or waiter bound. Retryable. | Retry later or raise the bounds. |
| `discovery/client_id_mismatch` | A client metadata document's `client_id` differs from its location. | Reject the document. |
| `discovery/connect_failed` | No connection could be made. Retryable. | Retry later. |
| `discovery/deadline_exceeded` | The fetch ran out of time. Retryable. | Retry later. |
| `discovery/directory_signature_invalid` | A key directory's possession proof does not verify. | Reject the directory. |
| `discovery/directory_unsigned` | A directory has no proof and the source requires one. | Reject, or opt out only for trusted test data. |
| `discovery/invalid_key_set` | The key set is malformed or contains a key the source refuses, such as a private or duplicate key. | Reject the response. |
| `discovery/invalid_options` | Options are malformed. | Fix the options. |
| `discovery/invalid_response` | The response is malformed: bad JSON, encoding, cache headers, or framing. | Reject the response. |
| `discovery/invalid_source` | A source description is malformed. | Fix the source. |
| `discovery/limit` | The response exceeds a size, key, or removal bound. | Reject, or raise the source limits. |
| `discovery/redirect_denied` | A redirect is not allowed: `maxRedirects` is 0, the `Location` is malformed, or it leaves `redirectScope`. | Fix the source URL, or allow the redirect. |
| `discovery/redirect_limit` | More redirects than `maxRedirects`. | Raise `maxRedirects` if intended. |
| `discovery/domain_not_found` | DNS answered authoritatively that the configured domain does not exist. Not marked retryable. | Fix the configured location. |
| `discovery/resolution_failed` | DNS resolution failed, transiently or otherwise. Retryable. | Retry, or check the DNS servers. |
| `discovery/revoked_key` | The key was removed or revoked. | Reject. |
| `discovery/source_unavailable` | No usable keys are available for the source now, such as a miss without a fetch function. Retryable. | Fetch or refresh the source. |
| `discovery/tls_failed` | The TLS handshake or certificate check failed. | Check the certificate and `cacerts`. |
| `discovery/transport_unavailable` | `cacerts: "os"` has no usable OS trust store: the runtime lacks the API (Node before 22.15.0), the store is empty, or access is denied. | Supply DER roots in `cacerts`, or run where the system store is available. |
| `discovery/unexpected_media_type` | The response content type does not match the source type. | Reject, or pass the correct `content-type`. |
| `discovery/unexpected_status` | The response status was not 200. Retryable for 5xx. | Retry 5xx later; reject 4xx. |
| `discovery/unknown_key` | The key set has no fresh, compatible key with that ID. | Reject, or refresh the set. |

## jose

Returned by `JWS`, `JWE`, `Nested`, and `KeyManagement`.

| Reason | Meaning | What to do |
| --- | --- | --- |
| `jose/crypto.deadline_exceeded` | The operation ran out of time. Retryable. | Retry with a fresh deadline. |
| `jose/crypto.decryption_failed` | Decryption failed. Every secret-dependent failure returns this one error. | Reject. |
| `jose/crypto.entropy_failure` | The runtime's random generator, or a recipient wrapper, reported an entropy failure. Not marked retryable. | Treat it as a runtime fault and check the runtime. |
| `jose/crypto.invalid_signature` | The signature does not verify, or is empty. | Reject. |
| `jose/crypto.signer_failed` | A signer or recipient function failed. | Fix the function. |
| `jose/input.algorithm_not_permitted` | The token's algorithm is not in your policy. | Reject, or allow it. |
| `jose/input.compression_unsupported` | The header carries `zip`. | Reject. |
| `jose/input.detached_payload` | The payload is empty or detached. | Reject. |
| `jose/input.duplicate_member` | The protected header repeats a member. | Reject. |
| `jose/input.invalid_base64` | A segment is not canonical base64url. | Reject. |
| `jose/input.invalid_header` | The protected header is malformed. | Reject. |
| `jose/input.invalid_iv` | The initialization vector is malformed. | Reject. |
| `jose/input.invalid_options` | Options are malformed. | Fix the options. |
| `jose/input.invalid_policy` | The policy is missing a key or has a bad value. | Fix the policy. |
| `jose/input.invalid_serialization` | The compact token has the wrong shape. | Reject. |
| `jose/input.invalid_tag` | The authentication tag is malformed. | Reject. |
| `jose/input.limit` | Input exceeds a size, depth, or member bound. | Reject. |
| `jose/input.unsupported_critical_header` | The header carries `crit`. | Reject. |
| `jose/input.unsupported_header` | The header carries `jku`, `x5u`, `jwk`, or `b64`; or, during JWE encryption, a recipient wrapper returned header members other than at most `iv` and `tag` (and those only for GCM key wrapping). | Reject the token, or fix the recipient wrapper. |
| `jose/input.unsupported_serialization` | The token uses JSON serialization. | Use compact serialization. |
| `jose/key.algorithm_mismatch` | The resolved or signing key is bound to another algorithm. | Return a key for the token's algorithm. |
| `jose/key.key_resolver_failed` | Your resolver threw or returned a malformed entry. | Fix the resolver. |
| `jose/key.unknown_key` | Your resolver returned an error. | Reject. |
| `jose/nesting.content_type_mismatch` | The outer `cty` is not one of your `content_types`. | Reject. |
| `jose/nesting.nesting_depth` | The inner token is not a single compact JWS, or the inner JWS carries `cty`. | Reject. |

## replay

Returned by replay claims, stores, and `Replay` helpers. During verification these become `core/replay.*` reasons.

| Reason | Meaning | What to do |
| --- | --- | --- |
| `replay/invalid_claim` | Claim bytes or retention are malformed. | Fix the claim. |
| `replay/invalid_options` | Options, a sweep time, or retention inputs are malformed. | Fix the input. |
| `replay/invalid_store` | A store port or PostgreSQL table name is malformed. | Fix the store. |
| `replay/store_failed` | The store failed. | Check the store. |
| `replay/store_full` | The store is full: the memory store reached `maxEntries`, or a caller store port returned `"full"`. | Sweep, or use a larger or shared store. |
| `replay/store_timeout` | The store operation ran out of time; it may have committed. | Treat the outcome as unknown. |
| `replay/store_unavailable` | The store could not be reached. | Check the database. |

## adapter

Returned by the Node HTTP and Fetch adapters. `stage` names the step and `attempt` the client attempt. `source` is set only when the adapter wraps a failed core, custody, or message Result, such as a rejected verification or signature; it is null when the adapter's own check failed, when the underlying error has another kind, or when an unexpected exception was caught. An expired Context is returned as `custody/deadline_exceeded`, not wrapped.

| Reason | Meaning | What to do |
| --- | --- | --- |
| `adapter/already_verified` | The request was already verified, or verification is in progress. | Read `verification(req)`. |
| `adapter/body_unavailable` | The body could not be read whole, its length disagrees with `Content-Length`, or a Fetch response policy requires content. | Check framing; on Fetch, use `content: "not_required"` for responses. |
| `adapter/cross_origin_redirect` | A redirect leaves the origin and is not in `allowedOrigins`. | Add the origin, or do not follow. |
| `adapter/digest_conflict` | Signing found an existing `Content-Digest` that disagrees. | Remove or fix the existing digest. |
| `adapter/invalid_options` | Options are malformed, or used in the wrong order. | Fix the call. |
| `adapter/invalid_request` | The request or URL is not acceptable here: on Fetch, a GET or HEAD with a body, an empty-query URL on Node below 24, or verification on a runtime outside `FETCH_VERIFICATION_RUNTIMES`; on Node, a URL with userinfo or a fragment, a method that is not a token, a value that is not a Node request, or `captureBody` on a request that is already captured. (A GET or HEAD body on the Node client is `invalid_options`.) | Fix the request, or verify on a supported runtime. |
| `adapter/limit` | The body exceeds `maxBytes`. | Reject, or answer 413. |
| `adapter/not_captured` | The request was not captured before verification. | Call `captureRequest` or `capture(server)` first. |
| `adapter/not_final_step` | Not returned here. | None. |
| `adapter/parser_order` | Another consumer read the request stream while capture owned it. | Capture before any body parser. |
| `adapter/request_rejected` | Request verification failed. `source` holds the core error when verification returned one, and is null when an unexpected exception was caught. | Map `source` when present; otherwise treat it as a failed verification. |
| `adapter/response_rejected` | Response verification failed. `source` holds the core error when verification returned one, and is null when an unexpected exception was caught. | Map `source` when present; otherwise treat it as a failed verification. |
| `adapter/signing_failed` | Signing failed. `source` holds the core or custody error when signing returned one, and is null when an unexpected exception was caught. | Map `source` when present; otherwise check the spec and signer. |
| `adapter/unsupported_component` | Fetch signing covers a field the runtime controls (`host`, `content-length`, `accept-encoding`, `connection`, `transfer-encoding`, `trailer`, `keep-alive`, `proxy-connection`, `te`, `upgrade`, and `sec-fetch-mode` on Node) or a `;tr` component. Node response signing covers `transfer-encoding`, `connection`, `trailer`, `keep-alive`, `proxy-connection`, `te`, or `upgrade`. Fetch verification refuses a policy or signature covering `@request-target`, `@target-uri`, `@path`, `@query`, `cookie`, or a `bs` or `tr` parameter, because Fetch cannot show those bytes as sent. | For signing, cover `@authority` instead of `host` and `content-digest` instead of `content-length`. For verification of those components, use the Node HTTP adapter or core `verify` with a Message built from the wire. |
| `adapter/unsupported_delivery` | The response cannot be signed as delivered: headers already sent, an informational status, or pending cookies covered. | Sign before writing the response. |
| `adapter/untrusted_proxy` | The socket peer is not in `trustedProxies`. | Add the proxy, or reject. |
