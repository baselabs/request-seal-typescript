import {encodeUtf8} from './runtime.ts';
import { digest as hash } from "./crypto/subtle.ts";
import { snapshotOptions } from "./brand.ts";
import { DIGEST_MAX_BYTES } from "./constants.ts";
import {
  parse as sfParse,
  parseField,
  serialize as sfSerialize,
  type Dictionary,
  type Schema,
  type Item,
} from "./structured-fields/index.ts";
import { isMessage, isBody, type Message, type Body } from "./message/index.ts";
import { digestError, isRequestSealError } from "./errors/types.ts";
import type { Reason } from "./errors/parity.ts";
import { ok, err, type Result } from "./result.ts";
/** Supported content-digest algorithm identifiers. */
export type DigestAlgorithm = "sha-256" | "sha-512";
/** Content or representation digest field selection. */
export type DigestKind = "content" | "representation";
/** A caller-owned incremental hashing session. */
export type HashSession = {
  /** Hash an owned chunk while enforcing state and total byte limits. */
  update: (chunk: Uint8Array) => void | Promise<void>;
  /** Finalize the selected digest algorithms into a canonical digest field. */
  finish: () => Uint8Array | Promise<Uint8Array>;
};
/** create, update, and finish must be own properties; bind class prototype methods explicitly. */
export type IncrementalHasher = {
  /** Create a bounded digest state after validating the incremental hasher. */
  create: (algorithm: DigestAlgorithm) => HashSession | Promise<HashSession>;
};
/** Verified digest kind, algorithms, section, and processed byte count. */
export type DigestFacts = Readonly<{
  kind: "content-digest" | "repr-digest";
  checked: readonly string[];
  bytes: number;
  unsupported: readonly string[];
}>;
const schema: Schema = Object.freeze({
  revision: "rfc8941",
  type: "dictionary",
  itemTypes: Object.freeze(["bytes"] as const),
  parameterTypes: Object.freeze([
    "integer",
    "decimal",
    "string",
    "token",
    "bytes",
    "boolean",
  ] as const),
  innerLists: false,
});
const algorithms = Object.freeze({
  "sha-256": Object.freeze({ name: "SHA-256", length: 32 }),
  "sha-512": Object.freeze({ name: "SHA-512", length: 64 }),
});
function fail(reason: Reason<"digest">): never {
  throw digestError(reason);
}
function ensure(value: unknown, reason: Reason<"digest">): asserts value {
  if (!value) fail(reason);
}
function error(e: unknown, fallback: Reason<"digest">) {
  return isRequestSealError(e) &&
    (e.kind === "digest" || e.kind === "structured_fields")
    ? e
    : digestError(fallback);
}
function selected(input: unknown): readonly DigestAlgorithm[] {
  ensure(Array.isArray(input), "unsupported_algorithm");
  const n = input.length;
  ensure(
    n >= 1 && n <= Object.keys(algorithms).length,
    "unsupported_algorithm",
  );
  const names = Array.from({ length: n }, (_, i) => input[i] as unknown);
  ensure(
    names.every((s) => typeof s === "string" && Object.hasOwn(algorithms, s)) &&
      new Set(names).size === n,
    "unsupported_algorithm",
  );
  return Object.freeze(names as DigestAlgorithm[]);
}
function maximum(options: unknown, stream = false): number {
  const r = snapshotOptions(options, ["maxBytes"]);
  ensure(r.ok, "invalid_options");
  const max = Object.hasOwn(r.value, "maxBytes")
    ? r.value.maxBytes
    : DIGEST_MAX_BYTES;
  ensure(
    typeof max === "number" &&
      Number.isSafeInteger(max) &&
      max >= 0 &&
      (stream || max <= DIGEST_MAX_BYTES),
    "invalid_options",
  );
  return max;
}
function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
function dictionary(
  entries: readonly (readonly [string, Uint8Array])[],
): Dictionary {
  return {
    kind: "dictionary",
    value: entries.map(([name, bytes]) => [
      name,
      { kind: "item", value: { kind: "bytes", value: bytes }, parameters: [] },
    ]),
  };
}
function validate(value: Dictionary): Result<Dictionary> {
  try {
    for (const [name, member] of value.value) {
      ensure(
        member.kind === "item" && member.value.kind === "bytes",
        "invalid_field",
      );
      if (Object.hasOwn(algorithms, name))
        ensure(
          member.value.value.length ===
            algorithms[name as DigestAlgorithm].length,
          "invalid_digest_length",
        );
    }
    return ok(value);
  } catch (e) {
    return err(error(e, "invalid_field"));
  }
}
/** Parse a Content-Digest dictionary and validate its members. */
export function parseDigest(bytes: unknown): Result<Dictionary> {
  const r = sfParse("dictionary", bytes, { schema });
  return r.ok ? validate(r.value as Dictionary) : r;
}
/** Serialize and validate a digest dictionary. */
export function serializeDigest(value: unknown): Result<Uint8Array> {
  const r = sfSerialize(value, { schema });
  if (!r.ok) return r;
  const parsed = parseDigest(r.value);
  return parsed.ok ? r : parsed;
}
/** Compute a canonical digest field for the selected algorithms. */
export async function digest(
  content: unknown,
  names: unknown,
  options: unknown = {},
): Promise<Result<Uint8Array>> {
  try {
    ensure(content instanceof Uint8Array, "invalid_body");
    const max = maximum(options),
      chosen = selected(names);
    ensure(content.length <= max, "limit");
    const bytes = new Uint8Array(content);
    const entries: [string, Uint8Array][] = [];
    for (const name of chosen)
      entries.push([
        name,
        new Uint8Array(await hash(algorithms[name].name, bytes)),
      ]);
    return serializeDigest(dictionary(entries));
  } catch (e) {
    return err(error(e, "invalid_state"));
  }
}
// Empty vectors: NIST CAVS 11.0 SHA byte test vectors (Len=0).
// https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Secure-Hashing
// "abc" vectors: RFC 6234 Section 8.5, SHA256 and SHA512 test 1.
const knownAnswers = Object.freeze({
  "sha-256": Object.freeze([
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  ]),
  "sha-512": Object.freeze([
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  ]),
});
const states = new WeakSet<object>();
/** Check the private brand of an incremental digest state. */
export function isDigestState(value: unknown): value is DigestState {
  return typeof value === "object" && value !== null && states.has(value);
}
const token = Object.freeze({});
const busySessions = new WeakSet<object>();
/** A branded, bounded incremental digest computation. */
export class DigestState {
  readonly kind: DigestKind;
  readonly maxBytes: number;
  #bytes = 0;
  #sessions: readonly (readonly [DigestAlgorithm, HashSession])[];
  #finished: Uint8Array | undefined;
  #invalid = false;
  #busy = false;
  constructor(
    t: object,
    kind: DigestKind,
    max: number,
    sessions: readonly (readonly [DigestAlgorithm, HashSession])[],
  ) {
    if (t !== token) throw new TypeError("Invalid digest state");
    this.kind = kind;
    this.maxBytes = max;
    this.#sessions = sessions;
    states.add(this);
    Object.freeze(this);
  }
  get bytes(): number {
    return this.#bytes;
  }
  /** Create a bounded digest state after validating the incremental hasher. */
  static async create(
    kind: unknown,
    names: unknown,
    hasher: unknown,
    options: unknown = {},
  ): Promise<Result<DigestState>> {
    try {
      ensure(kind === "content" || kind === "representation", "invalid_kind");
      const max = maximum(options, true),
        chosen = selected(names),
        port = snapshotOptions(hasher, ["create"]);
      ensure(
        port.ok && typeof port.value.create === "function",
        "invalid_state",
      );
      const create = (port.value.create as IncrementalHasher["create"]).bind(
        hasher,
      );
      const capture = async (name: DigestAlgorithm): Promise<HashSession> => {
        let h: HashSession;
        try { h = await create(name); } catch { fail("invalid_state"); }
        const s = snapshotOptions(h, ["update", "finish"]);
        ensure(
          s.ok &&
            typeof s.value.update === "function" &&
            typeof s.value.finish === "function",
          "invalid_state",
        );
        const update = (s.value.update as HashSession["update"]).bind(h),
          finish = (s.value.finish as HashSession["finish"]).bind(h);
        return Object.freeze({
          async update(chunk: Uint8Array) {
            ensure(!busySessions.has(h), "invalid_state");
            busySessions.add(h);
            try { ensure(await update(chunk) === undefined, "invalid_state"); }
            catch { fail("invalid_state"); }
            finally { busySessions.delete(h); }
          },
          async finish() {
            ensure(!busySessions.has(h), "invalid_state");
            busySessions.add(h);
            try { return await finish(); }
            catch { fail("invalid_state"); }
            finally { busySessions.delete(h); }
          },
        });
      };
      const sessions: [DigestAlgorithm, HashSession][] = [];
      // Compare the injected port to fixed published known answers.
      for (const name of Object.keys(algorithms) as DigestAlgorithm[])
        for (const [index, bytes] of [
          [new Uint8Array()],
          [encodeUtf8("a"), new Uint8Array(), encodeUtf8("bc")],
        ].entries()) {
          const session = await capture(name);
          for (const chunk of bytes) await session.update(new Uint8Array(chunk));
          const actual = await session.finish(),
            expected = new Uint8Array(
              knownAnswers[name][index]!.match(/../g)!.map((v) =>
                parseInt(v, 16),
              ),
            );
          ensure(
            actual instanceof Uint8Array && equal(actual, expected),
            "invalid_state",
          );
        }
      for (const name of chosen) sessions.push([name, await capture(name)]);
      return ok(new DigestState(token, kind, max, Object.freeze(sessions)));
    } catch (e) {
      return err(error(e, "invalid_state"));
    }
  }
  /** Hash an owned chunk while enforcing state and total byte limits. */
  async update(chunk: unknown): Promise<Result<DigestState>> {
    try {
      ensure(
        isDigestState(this) && !this.#invalid && !this.#finished && !this.#busy,
        "invalid_state",
      );
      ensure(chunk instanceof Uint8Array, "invalid_chunk");
      ensure(chunk.length <= this.maxBytes - this.#bytes, "limit");
      const bytes = new Uint8Array(chunk);
      this.#busy = true;
      try {
        for (const [, s] of this.#sessions)
          await s.update(new Uint8Array(bytes));
        this.#bytes += bytes.length;
      } catch {
        this.#invalid = true;
        fail("invalid_state");
      } finally {
        this.#busy = false;
      }
      return ok(this);
    } catch (e) {
      return err(error(e, "invalid_state"));
    }
  }
  /** Finalize the selected digest algorithms into a canonical digest field. */
  async finish(): Promise<Result<Uint8Array>> {
    try {
      ensure(
        isDigestState(this) && !this.#invalid && !this.#busy,
        "invalid_state",
      );
      if (this.#finished) return ok(new Uint8Array(this.#finished));
      this.#busy = true;
      try {
        const entries: [string, Uint8Array][] = [];
        for (const [name, s] of this.#sessions) {
          const bytes = await s.finish();
          ensure(
            bytes instanceof Uint8Array &&
              bytes.length === algorithms[name].length,
            "invalid_state",
          );
          entries.push([name, new Uint8Array(bytes)]);
        }
        const r = serializeDigest(dictionary(entries));
        if (!r.ok) throw r.error;
        this.#finished = new Uint8Array(r.value);
        return ok(new Uint8Array(r.value));
      } catch (e) {
        this.#invalid = true;
        throw e;
      } finally {
        this.#busy = false;
      }
    } catch (e) {
      return err(error(e, "invalid_state"));
    }
  }
  /** Return a bounded public inspection view without retained cryptographic bytes. */
  toJSON(): unknown {
    return { kind: this.kind, bytes: this.#bytes, maxBytes: this.maxBytes };
  }
}
Object.freeze(DigestState.prototype);
Object.freeze(DigestState);
export function digestField(
  message: Message,
  kind: DigestKind,
  section: "headers" | "trailers",
): Result<Dictionary> {
  const r = parseField(
    message,
    kind === "content" ? "content-digest" : "repr-digest",
    schema,
    section,
    { uniqueKeys: Object.keys(algorithms) },
  );
  if (!r.ok)
    return r.error.reason === "duplicate_key"
      ? err(digestError("conflicting_digest"))
      : r;
  return validate(r.value as Dictionary);
}
/** Check required digest fields against retained bytes or an incremental state. */
export async function checkDigest(
  message: unknown,
  kind: unknown,
  options: unknown = {},
): Promise<Result<DigestFacts>> {
  try {
    ensure(isMessage(message), "invalid_message");
    ensure(kind === "content" || kind === "representation", "invalid_kind");
    const o = snapshotOptions(options, [
      "section",
      "representation",
      "digestState",
      "maxBytes",
    ]);
    ensure(o.ok, "invalid_options");
    const a = o.value,
      section = Object.hasOwn(a, "section") ? a.section : "headers";
    ensure(section === "headers" || section === "trailers", "invalid_options");
    ensure(
      !(Object.hasOwn(a, "representation") && Object.hasOwn(a, "digestState")),
      "invalid_options",
    );
    const max = maximum(
      Object.hasOwn(a, "maxBytes") ? { maxBytes: a.maxBytes } : {},
    );
    const state = a.digestState;
    if (Object.hasOwn(a, "digestState"))
      ensure(isDigestState(state) && state.kind === kind, "invalid_state");
    else {
      ensure(
        kind === "representation" || !Object.hasOwn(a, "representation"),
        "invalid_options",
      );
      if (kind === "representation")
        ensure(Object.hasOwn(a, "representation"), "representation_required");
    }
    const body: Body =
      kind === "content" ? message.body : (a.representation as Body);
    if (!isDigestState(state)) {
      ensure(isBody(body), "invalid_body");
      ensure(
        body.state === "retained" && body.bytes instanceof Uint8Array,
        "body_unavailable",
      );
      ensure(body.bytes.length <= max, "limit");
    }
    const r = digestField(message, kind, section);
    if (!r.ok) return r;
    const expected = r.value;
    const names = expected.value
      .filter(([name]) => Object.hasOwn(algorithms, name))
      .map(([name]) => name);
    ensure(names.length > 0, "unsupported_algorithm");
    const actual = isDigestState(state)
      ? await state.finish()
      : await digest(body.bytes, names, { maxBytes: max });
    if (!actual.ok) return actual;
    const parsed = parseDigest(actual.value);
    if (!parsed.ok) return parsed;
    const computed = new Map(parsed.value.value);
    for (const [name, item] of expected.value)
      if (Object.hasOwn(algorithms, name)) {
        const member = computed.get(name);
        ensure(member, "uncomputed_algorithm");
        ensure(
          equal(
            (item as Item).value.value as Uint8Array,
            (member as Item).value.value as Uint8Array,
          ),
          "mismatch",
        );
      }
    return ok(
      Object.freeze({
        kind: kind === "content" ? "content-digest" : "repr-digest",
        checked: Object.freeze(names),
        bytes: isDigestState(state) ? state.bytes : body.bytes!.length,
        unsupported: Object.freeze(
          expected.value
            .filter(([name]) => !Object.hasOwn(algorithms, name))
            .map(([name]) => name),
        ),
      }),
    );
  } catch (e) {
    return err(error(e, "invalid_state"));
  }
}
/** Content-digest computation, parsing, serialization, and checking. */
export const Digest = Object.freeze({
  /** Compute the selected content digests over owned body bytes. */
  content: digest,
  /** Parse and validate the supported wire representation. */
  parse: parseDigest,
  /** Serialize validated values to their canonical wire representation. */
  serialize: serializeDigest,
  /** Check required content digests against retained body bytes. */
  check: checkDigest,
});
