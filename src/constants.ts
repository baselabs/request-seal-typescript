export const VERSION = '0.1.0';
export const CORPUS_PIN = Object.freeze({tag: 'v0.4.0', commit: 'b2392871933d99641a7cb2ca2726aefd20081dee', indexSha256: 'f37435eca377666ab45c2b8f580287263145268e03d9224c76e324e4afaded6f'});
// RequestSeal.StructuredFields ceilings at v0.4.0 (b239287).
export const STRUCTURED_FIELDS_LIMITS = Object.freeze({maxBytes: 65_536, maxMembers: 1024, maxInnerItems: 256, maxParameters: 256, maxKeyBytes: 256, maxValueBytes: 16_384, maxNodes: 4096});
// RequestSeal.JOSE.Support: 16,384 bytes, four containers deep, 64 entries per container.
// String bytes are bounded by the same complete-header byte ceiling.
export const JSON_LIMITS = Object.freeze({maxBytes: 16_384, maxDepth: 4, maxMembers: 64, maxArrayLength: 64, maxStringBytes: 16_384});
export const JOSE_MAX_COMPACT_BYTES = 1_048_576; // RequestSeal.JOSE.Support.bytes compact wire ceiling.
export const JOSE_MAX_PLAINTEXT_BYTES = 1_048_576; // RequestSeal.JOSE.Support.
export const BODY_MAX_BYTES = 1_048_576; // RequestSeal.Body default retention.
export const DIGEST_MAX_BYTES = 16_777_216; // RequestSeal.Digest default work ceiling.
export const SIGNATURE_BASE_MAX_BYTES = 1_048_576; // RequestSeal.SignatureBase.
export const SIGNATURE_BASE_MAX_COMPONENTS = 256; // RequestSeal.SignatureBase.
export const SIGNATURE_MAX_BYTES = 1024; // RequestSeal.SignatureFields (signature and nonce).
export const MESSAGE_MAX_TARGET_BYTES = 16_384; // RequestSeal.Message.
export const MESSAGE_MAX_FIELD_BYTES = 65_536; // RequestSeal.Message.Validation.
export const MESSAGE_MAX_FIELDS_BYTES = 1_048_576; // RequestSeal.Message.
export const QUORUM_MAX_NODES = 131_072; // RequestSeal.Quorum.Evaluation.
export const QUORUM_MAX_SIGNATURES = 64; // RequestSeal.Quorum.
export const DISCOVERY_DEFAULT_MAX_BYTES = 65_536; // RequestSeal.Discovery.Source.
export const DISCOVERY_MAX_BYTES = 1_048_576; // RequestSeal.Discovery.Source maximum.
export const CLOCK_MAX_SECONDS = 253_402_300_799; // Shared port contract, end of year 9999.
export const TIMEOUT_MAX_MS = 300_000; // RequestSeal.Custody and JOSE.Support.
export const TIMEOUT_DEFAULT_MS = 5000; // RequestSeal.Custody and JOSE.Support.
export const SF_MAX_INTEGER = 999_999_999_999_999; // RequestSeal.StructuredFields, RFC 9651.
export const PROFILE_MAX_MEMBERS = 8; // RequestSeal.Profile.
export const PROFILE_MAX_VALUE_BYTES = 256; // RequestSeal.Profile.
export const DISCOVERY_MAX_PERMITTED_ADDRESSES = 16; // RequestSeal.Discovery.Source.
export const DISCOVERY_MAX_KEYS = 256; // RequestSeal.Discovery.Source.
export const DISCOVERY_DEFAULT_MAX_KEYS = 32; // RequestSeal.Discovery.Source.
export const DISCOVERY_MAX_REDIRECTS = 3; // RequestSeal.Discovery.Source.
export const DISCOVERY_MAX_TTL_SECONDS = 604_800; // RequestSeal.Discovery.Source.
export const DISCOVERY_MAX_NEGATIVE_TTL_SECONDS = 300; // RequestSeal.Discovery.Source.
export const DISCOVERY_CIMD_MAX_BYTES = 5120; // RequestSeal.Discovery.Source.
// RequestSeal.PublicKey and Custody.Local container/component ceilings at v0.4.0 (b239287).
export const KEY_MAX_BYTES = 16_384;
export const KEY_MAX_MEMBERS = 32;
export const KEY_COMPONENT_MAX_ENCODED_BYTES = 21_846;
export const RSA_COMPONENT_MAX_ENCODED_BYTES = 1366;
export const RSA_MIN_BITS = 2048;
export const RSA_MAX_BITS = 8192;
export const RSA_MAX_EXPONENT = 0xffff_ffff;
export const KEY_IDENTITY_MAX_BYTES = 256;
export const HMAC_MIN_BYTES = 32;
export const HMAC_MAX_BYTES = 16_384;
// Owned codec traversal ceilings; complete container bytes remain bounded above.
export const DER_MAX_DEPTH = 32;
export const DER_MAX_NODES = 4096;
export const JWK_ALGORITHM_MAX_BYTES = 64;
export const JWK_MAX_OPERATIONS = 8;

export const CUSTODY_SIGNATURE_MAX_BYTES = 16_384; // RequestSeal.Custody verify and successful signature bounds.
export const MESSAGE_MAX_OCCURRENCES = 1024; // Headers and trailers combined.
export const MESSAGE_MAX_TOKEN_BYTES = 256; // Method and field names.
export const MESSAGE_MAX_SCHEME_BYTES = 64;
export const MESSAGE_MAX_AUTHORITY_BYTES = 1024;
export const MESSAGE_MAX_URL_BYTES = MESSAGE_MAX_TARGET_BYTES + MESSAGE_MAX_AUTHORITY_BYTES + MESSAGE_MAX_SCHEME_BYTES + 8;
export const SIGNATURE_DEFAULT_MAX_MEMBERS = 16; // RequestSeal.Authentication signing dictionary ceiling.
export const FRESHNESS_MAX_SKEW_SECONDS = 86_400; // RequestSeal.Policy.
export const SIGNING_NONCE_BYTES = 32; // RequestSeal.Signing entropy length.
