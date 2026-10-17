import { remainingMs, type Context } from "../context.ts";
import { decodeJson, type JsonNode } from "../json.ts";
import { PublicKey } from "../public_key.ts";
import {
  resolveAlgorithm,
  assertedJose,
  joseId,
  type JwsAlgorithm,
  selection, type SigningAlgorithm,
} from "../crypto/algorithm.ts";
import { digest } from "../crypto/subtle.ts";
import { encodeBase64Url } from "../bytes.ts";
import { ok, type Result } from "../result.ts";
import {
  isDiscoverySource,
  keyIdValid,
  type DiscoverySource,
  sourceOrigin,
  sourceUrl,
} from "./source.ts";
import {
  ensure,
  unwrap,
  failure,
  clockSeconds,
  inspectable,
  systemClock,
  list,
} from "./support.ts";
/** Discovery proof status. @inline */
export type Proof = "signed" | "unsigned" | "not_applicable";
/** A conditional revalidation outcome: the stored representation is unchanged (RFC 9111 Section 4.3.4). */
export type NotModified = Readonly<{notModified: true; etag: string; fetchedAt: number; expiresAt: number}>;
/** A branded resolved public key with origin, proof, and expiration facts. */
export type Resolution = Readonly<{
  key: PublicKey;
  keyId: string;
  thumbprint: string;
  algorithm: SigningAlgorithm;
  /** The source's alg assertion normalized once at import to its JOSE name. */
  assertedAlgorithm: JwsAlgorithm | null;
  origin: string;
  sourceType: DiscoverySource["type"];
  location: string;
  fetchedAt: number;
  expiresAt: number;
  proof: Proof;
  revision: string | null;
}>;
const resolutions = new WeakSet<object>(),
  sets = new WeakSet<object>();
/** Check the private brand of a discovery resolution. */
export function isResolution(v: unknown): v is Resolution {
  return !!v && typeof v === "object" && resolutions.has(v);
}
/** Check the private brand of a discovery key set. */
export function isKeySet(v: unknown): v is KeySet {
  return !!v && typeof v === "object" && sets.has(v);
}
export function resolution(data: Resolution): Resolution {
  const out = Object.assign(Object.create(null), data) as Resolution;
  resolutions.add(out);
  return inspectable(out, {
    kind: "Resolution",
    algorithm: data.algorithm,
    sourceType: data.sourceType,
    proof: data.proof,
  });
}
/** A branded immutable discovery key set with bounded key lookup. */
export type KeySet = Readonly<{
  source: DiscoverySource;
  origin: string;
  keys: Readonly<Record<string, Resolution>>;
  fetchedAt: number;
  expiresAt: number;
  revision: string;
  proof: Proof;
  /** The source's ETag validator, if it sent one; the cache revalidates with it. */
  etag: string | null;
  /** Resolve an eligible key by identifier, allowed algorithms, and current time. */
  lookup: (
    keyId: unknown,
    algorithms: unknown,
    now?: number,
  ) => Promise<Result<Resolution>>;
}>;
export function algorithmList(input: unknown): readonly SigningAlgorithm[] {
  return Object.freeze(Array.from(list(input, 64, 1), v => {
    const r = resolveAlgorithm(v);
    ensure(r.ok, 'invalid_options');
    return selection(r.value) as SigningAlgorithm;
  }));
}

export function keySet(data: Omit<KeySet, "lookup">): KeySet {
  const out = Object.assign(Object.create(null), data) as KeySet;
  Object.defineProperty(out, "lookup", {
    enumerable: false,
    value: (kid: unknown, allowed: unknown, now = systemClock()) =>
      lookup(out, kid, allowed, now),
  });
  sets.add(out);
  return inspectable(out, {
    kind: "KeySet",
    fetchedAt: data.fetchedAt,
    expiresAt: data.expiresAt,
    proof: data.proof,
  });
}
/** Resolve an eligible key by identifier, allowed algorithms, and current time. */
export async function lookup(
  set: unknown,
  kid: unknown,
  allowed: unknown,
  now = systemClock(),
  transient = false,
): Promise<Result<Resolution>> {
  try {
    ensure(isKeySet(set), "invalid_options");
    const choices = algorithmList(allowed);
    ensure(clockSeconds(now), "invalid_options");
    ensure(
      keyIdValid(set.source, kid) && (transient || now < set.expiresAt),
      "unknown_key",
    );
    const entry = Object.hasOwn(set.keys, kid) ? set.keys[kid] : undefined;
    ensure(
      entry &&
        isResolution(entry) &&
        now < entry.expiresAt &&
        !set.source.revoked.includes(entry.thumbprint),
      "unknown_key",
    );
    const algorithm = choices.find(
      (a) =>
        (entry.assertedAlgorithm === null ||
          entry.assertedAlgorithm === joseId(a)) &&
        entry.key.bind(a).ok,
    );
    ensure(algorithm, "unknown_key");
    return ok(resolution({ ...entry, algorithm, revision: set.revision }));
  } catch (e) {
    return failure(e, "unknown_key");
  }
}
function plain(node: JsonNode): unknown {
  if (node === null || typeof node !== "object") return node;
  if (node.kind === "number") return node;
  if (node.kind === "array") return node.items.map(plain);
  const out = Object.create(null) as Record<string, unknown>;
  for (const [k, v] of node.pairs) out[k] = plain(v);
  return out;
}
export function bodyDocument(
  bytes: unknown,
  source: DiscoverySource,
): Record<string, unknown> {
  ensure(bytes instanceof Uint8Array, "invalid_response");
  const cap =
    source.type === "cimd"
      ? Math.min(5120, source.maxDecodedBytes)
      : source.maxDecodedBytes;
  ensure(bytes.length <= cap, "limit");
  const decoded = decodeJson(bytes, {
    maxBytes: cap,
    maxDepth: 32,
    maxMembers: 256,
    maxArrayLength: 256,
    maxStringBytes: cap,
  });
  if (!decoded.ok)
    ensure(
      false,
      decoded.error.reason === "limit" ? "limit" : "invalid_response",
    );
  ensure(decoded.value.duplicates.length === 0, "invalid_response");
  const doc = plain(decoded.value.node);
  ensure(
    doc && typeof doc === "object" && !Array.isArray(doc),
    source.type === "cimd" ? "client_id_mismatch" : "invalid_key_set",
  );
  return doc as Record<string, unknown>;
}
function keyTime(v: unknown): number {
  ensure(
    v &&
      typeof v === "object" &&
      Object.hasOwn(v, "kind") &&
      Object.hasOwn(v, "lexeme"),
    "invalid_key_set",
  );
  const n = v as { kind: unknown; lexeme: unknown };
  ensure(
    n.kind === "number" &&
      typeof n.lexeme === "string" &&
      /^-?(0|[1-9][0-9]*)$/.test(n.lexeme),
    "invalid_key_set",
  );
  const t = Number(n.lexeme);
  ensure(
    Number.isSafeInteger(t) && t >= 0 && t <= 999_999_999_999_999,
    "invalid_key_set",
  );
  return t;
}
export async function bodyKeys(
  doc: Record<string, unknown>,
  source: DiscoverySource,
  now: number,
  location = source.location,
  context?: Context,
): Promise<Readonly<Record<string, Resolution>>> {
  ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
  ensure(Array.isArray(doc.keys), "invalid_key_set");
  ensure(doc.keys.length <= source.maxKeys, "limit");
  const keys = Object.create(null) as Record<string, Resolution>;
  for (const input of doc.keys) {
    ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
    ensure(
      input &&
        typeof input === "object" &&
        !Array.isArray(input) &&
        Object.keys(input).length <= 32,
      "invalid_key_set",
    );
    const j = input as Record<string, unknown>,
      asserted = j.alg;
    // Leaked private members are a publisher blunder the whole set rejects
    // loudly, before any skip decision: skipping must never hide them.
    ensure(
      !["d", "p", "q", "dp", "dq", "qi", "oth", "k"].some((k) =>
        Object.hasOwn(j, k),
      ),
      "invalid_key_set",
    );
    // A key whose alg names an algorithm this verifier does not use — an
    // encryption key, or a signing name outside both registries — cannot
    // satisfy any signature policy: skip it and keep the rest of the set.
    if (typeof asserted === "string" && assertedJose(asserted) === undefined)
      continue;
    ensure(
      asserted === undefined ||
        asserted === null ||
        typeof asserted === "string",
      "invalid_key_set",
    );
    // RFC 7517 sources assert standard JOSE names; either spelling normalizes
    // once, here, to the JOSE name, which exists for every registry entry.
    const normalized =
      typeof asserted === "string" ? assertedJose(asserted) : undefined;
    const imported = Object.assign(Object.create(null), j) as Record<
      string,
      unknown
    >;
    if (normalized !== undefined) imported.alg = normalized;
    const attempt = await PublicKey.import(imported);
    if (!attempt.ok) {
      // A well-formed key this verifier cannot import for signature work (an
      // unknown kty or curve, RFC 7517 Section 5) is skipped like an
      // out-of-registry alg; other import failures stay set rejections.
      if (attempt.error.kind !== "crypto" || attempt.error.reason !== "invalid_key")
        ensure(false, "invalid_key_set");
      ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
      continue;
    }
    const key = attempt.value;
    ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
    const thumbprint = unwrap(await key.thumbprint(), "invalid_key_set");
    ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
    const kid = source.keyId === "directory" ? j.kid : thumbprint;
    ensure(keyIdValid(source, kid), "invalid_key_set");
    ensure(
      source.keyId === "directory" ||
        !Object.hasOwn(j, "kid") ||
        j.kid === thumbprint,
      "invalid_key_set",
    );
    const nbf = Object.hasOwn(j, "nbf") ? keyTime(j.nbf) : null,
      exp = Object.hasOwn(j, "exp") ? keyTime(j.exp) : null;
    const publicJwk = unwrap(key.jwk(), "invalid_key_set");
    const algorithm: SigningAlgorithm =
      normalized === undefined
        ? (publicJwk.kty === "OKP"
            ? "ed25519"
            : publicJwk.kty === "EC"
              ? publicJwk.crv === "P-256"
                ? "ecdsa-p256-sha256"
                : "ecdsa-p384-sha384"
              : "rsa-pss-sha512")
        : { jws: normalized };
    if (
      key.bind(algorithm).ok &&
      (nbf === null || now >= nbf) &&
      (exp === null || now < exp) &&
      !source.revoked.includes(thumbprint)
    ) {
      ensure(!Object.hasOwn(keys, kid), "invalid_key_set");
      keys[kid] = resolution({
        key,
        keyId: kid,
        thumbprint,
        algorithm,
        assertedAlgorithm: normalized ?? null,
        origin: sourceOrigin(sourceUrl(location)),
        sourceType: source.type,
        location,
        fetchedAt: now,
        expiresAt: Math.min(now + source.maxTtl, exp ?? now + source.maxTtl),
        proof: "not_applicable",
        revision: null,
      });
    }
  }
  return Object.freeze(keys);
}
export async function parseBody(
  bytes: unknown,
  source: unknown,
  now: unknown,
): Promise<Result<Readonly<Record<string, Resolution>>>> {
  try {
    ensure(
      isDiscoverySource(source) &&
        (source.type === "directory" || source.type === "jwks_uri"),
      "invalid_source",
    );
    ensure(
      source.type !== "directory" || !source.requireSignedDirectory,
      "directory_unsigned",
    );
    ensure(bytes instanceof Uint8Array, "invalid_response");
    ensure(bytes.length <= source.maxBytes, "limit");
    ensure(clockSeconds(now), "invalid_options");
    const owned = new Uint8Array(bytes);
    return ok(await bodyKeys(bodyDocument(owned, source), source, now));
  } catch (e) {
    return failure(e);
  }
}
export async function revision(bytes: Uint8Array): Promise<string> {
  return encodeBase64Url(
    new Uint8Array(await digest("SHA-256", new Uint8Array(bytes))),
  );
}
