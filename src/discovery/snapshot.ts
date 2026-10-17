import { remainingMs, type Context } from "../context.ts";
import { ok, type Result } from "../result.ts";
import {
  createSource,
  sourceOrigin,
  sourceUrl,
  type DiscoverySource,
} from "./source.ts";
import {
  bodyDocument,
  bodyKeys,
  keySet,
  resolution,
  revision,
  type KeySet,
} from "./body.ts";
import { fields, expiry, header, mediaType, type Headers } from "./headers.ts";
import { possessionProof } from "./proof.ts";
import { ensure, unwrap, failure, clockSeconds } from "./support.ts";
import { decodeBody } from "./gzip.ts";
/** Caller owns fetching/address policy; a snapshot never starts a connection. */
export async function fromSnapshot(
  config: unknown,
  bodyBytes: unknown,
  fetchedAt: unknown,
  headers: unknown = [],
): Promise<Result<KeySet>> {
  try {
    const source = unwrap(createSource(config), "invalid_source");
    ensure(bodyBytes instanceof Uint8Array, "invalid_response");
    ensure(bodyBytes.length <= source.maxBytes, "limit");
    ensure(clockSeconds(fetchedAt), "invalid_options");
    const encoded = new Uint8Array(bodyBytes);
    const fs = fields(headers);
    mediaType(fs, source.type);
    const decoded = await decodeBody(
      encoded,
      header(fs, "content-encoding"),
      source.type === "cimd"
        ? Math.min(source.maxDecodedBytes, 5120)
        : source.maxDecodedBytes,
    );
    return await fromResource(
      source,
      decoded,
      encoded,
      fetchedAt,
      fs,
      source.location,
    );
  } catch (e) {
    return failure(e);
  }
}
export async function fromResource(
  source: DiscoverySource,
  decoded: Uint8Array,
  encoded: Uint8Array,
  now: number,
  fs: ReturnType<typeof fields>,
  location: string,
  outerExpiry?: number,
  nested = false,
  context?: Context,
): Promise<Result<KeySet>> {
  try {
    ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
    const bodySource =
      source.type === "cimd" && nested
        ? unwrap(
            createSource({ ...source, type: "jwks_uri", location }),
            "invalid_source",
          )
        : source;
    let doc = bodyDocument(decoded, bodySource);
    if (source.type === "cimd" && !nested) {
      ensure(doc.client_id === source.location, "client_id_mismatch");
      ensure(
        !(Object.hasOwn(doc, "jwks") && Object.hasOwn(doc, "jwks_uri")),
        "ambiguous_key_source",
      );
      ensure(!Object.hasOwn(doc, "jwks_uri"), "source_unavailable");
      ensure(
        doc.jwks && typeof doc.jwks === "object" && !Array.isArray(doc.jwks),
        "invalid_key_set",
      );
      doc = doc.jwks as Record<string, unknown>;
    }
    const parsed = await bodyKeys(doc, source, now, location, context);
    ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
    const proven =
      source.type === "directory"
        ? await possessionProof(source, parsed, location, fs, encoded, now, context)
        : { proof: "not_applicable" as const, expiresAt: now + source.maxTtl };
    ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
    let expiresAt = Math.min(
      expiry(fs, source, now),
      proven.expiresAt,
      outerExpiry ?? Infinity,
    );
    const keys = Object.create(null) as Record<string, (typeof parsed)[string]>;
    for (const [kid, entry] of Object.entries(parsed)) {
      keys[kid] = resolution({
        ...entry,
        proof: proven.proof,
        expiresAt: Math.min(entry.expiresAt, proven.expiresAt),
      });
      expiresAt = Math.min(expiresAt, keys[kid]!.expiresAt);
    }
    const bodyRevision = await revision(decoded);
    ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
    const storedEtag = header(fs, "etag");
    ensure(
      storedEtag === null || storedEtag.length <= 512,
      "invalid_response",
    );
    return ok(
      keySet({
        source,
        origin: sourceOrigin(sourceUrl(location)),
        keys: Object.freeze(keys),
        fetchedAt: now,
        expiresAt,
        revision: bodyRevision,
        proof: proven.proof,
        etag: storedEtag,
      }),
    );
  } catch (e) {
    return failure(e);
  }
}
export type { Headers };
