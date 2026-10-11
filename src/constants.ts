/** The public package version. */
export const VERSION = '0.1.0';
/** The immutable public conformance corpus release and index digest. */
export const CORPUS_PIN = Object.freeze({tag: 'v0.4.0', commit: 'b2392871933d99641a7cb2ca2726aefd20081dee', indexSha256: 'f37435eca377666ab45c2b8f580287263145268e03d9224c76e324e4afaded6f'});
// RequestSeal.StructuredFields ceilings at v0.4.0 (b239287).
/** Default bounded Structured Fields parser limits. */
export const STRUCTURED_FIELDS_LIMITS = Object.freeze({maxBytes: 65_536, maxMembers: 1024, maxInnerItems: 256, maxParameters: 256, maxKeyBytes: 256, maxValueBytes: 16_384, maxNodes: 4096});
// RequestSeal.JOSE.Support: 16,384 bytes, four containers deep, 64 entries per container.
// String bytes are bounded by the same complete-header byte ceiling.
/** Default bounded JSON parser limits. */
export const JSON_LIMITS = Object.freeze({maxBytes: 16_384, maxDepth: 4, maxMembers: 64, maxArrayLength: 64, maxStringBytes: 16_384});
/** Maximum compact JOSE wire bytes. */
export const JOSE_MAX_COMPACT_BYTES = 1_048_576; // RequestSeal.JOSE.Support.bytes compact wire ceiling.
/** Maximum JOSE plaintext bytes. */
export const JOSE_MAX_PLAINTEXT_BYTES = 1_048_576; // RequestSeal.JOSE.Support.
/** Default maximum retained body bytes. */
export const BODY_MAX_BYTES = 1_048_576; // RequestSeal.Body default retention.
/** Default maximum digest input bytes. */
export const DIGEST_MAX_BYTES = 16_777_216; // RequestSeal.Digest default work ceiling.
/** Fixed maximum cryptographic input byte limit. */
export const CRYPTO_MAX_BYTES_CEILING = 16_777_216; // RequestSeal.Crypto.max_bytes_ceiling at v0.4.1.
/** Default cryptographic input byte limit. */
export const CRYPTO_DEFAULT_MAX_BYTES = 1_048_576; // Independent of the fixed SignatureBase ceiling.
/** Maximum signature-base bytes. */
export const SIGNATURE_BASE_MAX_BYTES = 1_048_576; // RequestSeal.SignatureBase.
/** Maximum covered signature-base components. */
export const SIGNATURE_BASE_MAX_COMPONENTS = 256; // RequestSeal.SignatureBase.
/** Maximum encoded signature or nonce bytes. */
export const SIGNATURE_MAX_BYTES = 1024; // RequestSeal.SignatureFields (signature and nonce).
/** Maximum raw HTTP target bytes. */
export const MESSAGE_MAX_TARGET_BYTES = 16_384; // RequestSeal.Message.
/** Maximum bytes in one HTTP field. */
export const MESSAGE_MAX_FIELD_BYTES = 65_536; // RequestSeal.Message.Validation.
/** Maximum total HTTP field bytes. */
export const MESSAGE_MAX_FIELDS_BYTES = 1_048_576; // RequestSeal.Message.
/** Maximum quorum evaluation nodes. */
export const QUORUM_MAX_NODES = 131_072; // RequestSeal.Quorum.Evaluation.
/** Maximum signatures evaluated by a quorum. */
export const QUORUM_MAX_SIGNATURES = 64; // RequestSeal.Quorum.
/** Default maximum discovery response bytes. */
export const DISCOVERY_DEFAULT_MAX_BYTES = 65_536; // RequestSeal.Discovery.Source.
/** Fixed maximum discovery response bytes. */
export const DISCOVERY_MAX_BYTES = 1_048_576; // RequestSeal.Discovery.Source maximum.
/** Maximum supported Unix timestamp in seconds. */
export const CLOCK_MAX_SECONDS = 253_402_300_799; // Shared port contract, end of year 9999.
/** Maximum operation timeout in milliseconds. */
export const TIMEOUT_MAX_MS = 300_000; // RequestSeal.Custody and JOSE.Support.
/** Default operation timeout in milliseconds. */
export const TIMEOUT_DEFAULT_MS = 5000; // RequestSeal.Custody and JOSE.Support.
/** Maximum absolute Structured Fields integer value. */
export const SF_MAX_INTEGER = 999_999_999_999_999; // RequestSeal.StructuredFields, RFC 9651.
/** Maximum profile metadata members. */
export const PROFILE_MAX_MEMBERS = 8; // RequestSeal.Profile.
/** Maximum profile metadata value bytes. */
export const PROFILE_MAX_VALUE_BYTES = 256; // RequestSeal.Profile.
/** Maximum profile name or key code points. */
export const PROFILE_MAX_ATOM_CODE_POINTS = 255; // BEAM atom limit for profile names and keys.
/** Maximum explicitly permitted discovery addresses. */
export const DISCOVERY_MAX_PERMITTED_ADDRESSES = 16; // RequestSeal.Discovery.Source.
/** Fixed maximum discovery keys per source. */
export const DISCOVERY_MAX_KEYS = 256; // RequestSeal.Discovery.Source.
/** Default maximum discovery keys per source. */
export const DISCOVERY_DEFAULT_MAX_KEYS = 32; // RequestSeal.Discovery.Source.
/** Maximum discovery redirect hops. */
export const DISCOVERY_MAX_REDIRECTS = 3; // RequestSeal.Discovery.Source.
/** Maximum discovery cache lifetime in seconds. */
export const DISCOVERY_MAX_TTL_SECONDS = 604_800; // RequestSeal.Discovery.Source.
/** Maximum negative discovery cache lifetime in seconds. */
export const DISCOVERY_MAX_NEGATIVE_TTL_SECONDS = 300; // RequestSeal.Discovery.Source.
/** Maximum client metadata document bytes. */
export const DISCOVERY_CIMD_MAX_BYTES = 5120; // RequestSeal.Discovery.Source.
// RequestSeal.PublicKey and Custody.Local container/component ceilings at v0.4.0 (b239287).
/** Maximum encoded key container bytes. */
export const KEY_MAX_BYTES = 16_384;
/** Maximum key container members. */
export const KEY_MAX_MEMBERS = 32;
/** Maximum encoded public key component bytes. */
export const KEY_COMPONENT_MAX_ENCODED_BYTES = 21_846;
/** Maximum encoded RSA component bytes. */
export const RSA_COMPONENT_MAX_ENCODED_BYTES = 1366;
/** Minimum permitted RSA modulus bits. */
export const RSA_MIN_BITS = 2048;
/** Maximum permitted RSA modulus bits. */
export const RSA_MAX_BITS = 8192;
/** Maximum permitted RSA public exponent. */
export const RSA_MAX_EXPONENT = 0xffff_ffff;
/** Maximum caller-supplied key identity bytes. */
export const KEY_IDENTITY_MAX_BYTES = 256;
/** Minimum HMAC secret bytes. */
export const HMAC_MIN_BYTES = 32;
/** Maximum HMAC secret bytes. */
export const HMAC_MAX_BYTES = 16_384;
// Owned codec traversal ceilings; complete container bytes remain bounded above.
/** Maximum DER container nesting depth. */
export const DER_MAX_DEPTH = 32;
/** Maximum DER traversal nodes. */
export const DER_MAX_NODES = 4096;
/** Maximum JWK algorithm identifier bytes. */
export const JWK_ALGORITHM_MAX_BYTES = 64;
/** Maximum JWK operation identifiers. */
export const JWK_MAX_OPERATIONS = 8;

/** Maximum custody signature bytes. */
export const CUSTODY_SIGNATURE_MAX_BYTES = 16_384; // RequestSeal.Custody verify and successful signature bounds.
/** Maximum combined HTTP header and trailer occurrences. */
export const MESSAGE_MAX_OCCURRENCES = 1024; // Headers and trailers combined.
/** Maximum HTTP method or field-name bytes. */
export const MESSAGE_MAX_TOKEN_BYTES = 256; // Method and field names.
/** Maximum HTTP scheme bytes. */
export const MESSAGE_MAX_SCHEME_BYTES = 64;
/** Maximum HTTP authority bytes. */
export const MESSAGE_MAX_AUTHORITY_BYTES = 1024;
/** Maximum combined HTTP URL bytes. */
export const MESSAGE_MAX_URL_BYTES = MESSAGE_MAX_TARGET_BYTES + MESSAGE_MAX_AUTHORITY_BYTES + MESSAGE_MAX_SCHEME_BYTES + 8;
/** Default maximum signature dictionary members. */
export const SIGNATURE_DEFAULT_MAX_MEMBERS = 16; // RequestSeal.Authentication signing dictionary ceiling.
/** Maximum freshness clock skew in seconds. */
export const FRESHNESS_MAX_SKEW_SECONDS = 86_400; // RequestSeal.Policy.
/** Random nonce bytes generated during signing. */
export const SIGNING_NONCE_BYTES = 32; // RequestSeal.Signing entropy length.
