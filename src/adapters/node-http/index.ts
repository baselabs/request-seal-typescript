import {
  IncomingMessage,
  request as httpRequest,
  type Server,
  ServerResponse,
} from "node:http";
import { request as httpsRequest } from "node:https";
import { Http2ServerRequest, Http2ServerResponse } from "node:http2";
import { TLSSocket } from "node:tls";
import { Readable } from "node:stream";
import { createHash } from "node:crypto";
import {
  Message,
  type FieldOccurrence,
  type Message as HttpMessage,
  token,
} from "../../message/index.ts";
import { sign } from "../../sign.ts";
import { verify } from "../../verify.ts";
import { verifyQuorum as coreVerifyQuorum } from "../../verify-quorum.ts";
import type { QuorumVerification } from "../../quorum/verification.ts";
import { verifyWebBotAuth as coreVerifyWebBotAuth } from "../../web-bot-auth/verify.ts";
import type { WebBotAuthVerification } from "../../web-bot-auth/verification.ts";
export type { WebBotAuthVerification } from "../../web-bot-auth/verification.ts";
import { parseAddress } from "../../discovery/address.ts";
import type { Verification } from "../../verification.ts";
import { isPolicy } from "../../policy.ts";
import { isAcceptSignature } from "../../accept-signature.ts";
import { type Context, run } from "../../context.ts";
import { err, ok, type Result } from "../../result.ts";
import {
  MESSAGE_MAX_FIELD_BYTES,
  MESSAGE_MAX_FIELDS_BYTES,
  MESSAGE_MAX_OCCURRENCES,
} from "../../constants.ts";
import * as S from "../support.ts";
import { deepFreeze } from "../../brand.ts";
type Request = IncomingMessage | Http2ServerRequest;
export type Ingress = Readonly<{
  evidence: "observed";
  httpVersion: string;
  tls: "plain" | "tls";
  protocol: string | null;
  alpn: string | null;
  remoteAddress: string | null;
  method: string;
  rawTarget: string;
  authority: string;
  scheme: string;
  declaredScheme: string | null;
}>;
export type Capture = Readonly<{
  message: HttpMessage;
  ingress: Ingress;
  origin: Readonly<{
    scheme: string;
    authority: string;
    source: "connection" | "forwarded";
  }>;
  replay: () => Result<Readable>;
}>;
export type VerifiedRequest = Readonly<{
  capture: Capture;
  verification: Verification;
  bytes: Uint8Array;
}>;
export type VerifiedQuorumRequest = Readonly<{
  capture: Capture;
  verification: QuorumVerification;
  bytes: Uint8Array;
}>;
export type VerifiedWebBotAuthRequest = Readonly<{
  capture: Capture;
  verification: WebBotAuthVerification;
  bytes: Uint8Array;
}>;
export type ClientResponse = Readonly<{
  request: HttpMessage;
  message: HttpMessage;
  status: number;
  bytes: Uint8Array;
}>;
const captures = new WeakMap<object, Promise<Result<Capture>>>();
const states = new WeakMap<
  object,
  {
    capture: Capture;
    stream?: Readable;
    read: boolean;
    done: boolean;
    hash: ReturnType<typeof createHash>;
    verified?: Result<VerifiedRequest | VerifiedQuorumRequest | VerifiedWebBotAuthRequest>;
  }
>();
const branded = new WeakSet<object>();
const verified = new WeakSet<object>();
const clientResponses = new WeakSet<object>();
const registrations = new WeakSet<object>();
function pairs(
  raw: readonly string[],
  section: "headers" | "trailers",
  h2: boolean,
) {
  S.need(
    raw.length % 2 === 0 && raw.length / 2 <= MESSAGE_MAX_OCCURRENCES,
    "node-http",
    "capture",
    "limit",
  );
  let size = 0;
  const out: {
    name: string;
    value: string;
    section: typeof section;
    provenance: "http1" | "http2";
  }[] = [];
  for (let i = 0; i < raw.length; i += 2) {
    const name = raw[i]!,
      value = raw[i + 1]!;
    if (name.startsWith(":")) continue;
    size += name.length + value.length;
    S.need(
      value.length <= MESSAGE_MAX_FIELD_BYTES &&
        size <= MESSAGE_MAX_FIELDS_BYTES,
      "node-http",
      "capture",
      "limit",
    );
    if (h2 && name.toLowerCase() === "cookie") {
      const prior = out.find((p) => p.name.toLowerCase() === "cookie");
      if (prior) {
        size += 2;
        S.need(
          size <= MESSAGE_MAX_FIELDS_BYTES,
          "node-http",
          "capture",
          "limit",
        );
        prior.value += "; " + value;
        continue;
      }
    }
    out.push({ name, value, section, provenance: h2 ? "http2" : "http1" });
  }
  return out;
}
function normalized(scheme: string, authority: string) {
  scheme = scheme.toLowerCase();
  authority = authority.toLowerCase();
  const p = /^(\[[^\]]+\]|[^:]+):([0-9]+)$/.exec(authority);
  if (p && Number(p[2]) === (scheme === "https" ? 443 : 80)) authority = p[1]!;
  return { scheme, authority };
}
function split(input: string, separator: string): string[] {
  let quoted = false,
    escaped = false,
    start = 0;
  const out: string[] = [];
  for (let i = 0; i < input.length; i++) {
    const c = input[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quoted && c === "\\") {
      escaped = true;
      continue;
    }
    if (c === '"') quoted = !quoted;
    else if (c === separator && !quoted) {
      out.push(input.slice(start, i).trim());
      start = i + 1;
    }
  }
  S.need(!quoted && !escaped, "node-http", "capture", "invalid_request");
  out.push(input.slice(start).trim());
  return out;
}
function cidr(value: unknown) {
  if (typeof value !== "string") return;
  const parts = value.split("/");
  if (parts.length > 2) return;
  const address = parseAddress(parts[0]);
  if (!address) return;
  const width = address.family === 4 ? 32 : 128;
  const prefix = parts.length === 1
    ? width
    : /^[0-9]+$/.test(parts[1]!)
    ? Number(parts[1])
    : -1;
  if (prefix < 0 || prefix > width) return;
  return { number: address.number, width, prefix };
}
function contains(network: unknown, peer: string | null): boolean {
  const a = cidr(network), b = parseAddress(peer);
  if (!a || !b) return false;
  let n = b.number;
  if (a.width === 32 && b.family === 6) {
    if (n >> 32n !== 0xffffn) return false;
    n &= 0xffffffffn;
  } else if (a.width === 128 && b.family === 4) {
    if (a.prefix > 96 && a.number >> 32n !== 0xffffn) return false;
    n += 0xffffn << 32n;
  }
  return a.number >> BigInt(a.width - a.prefix) ===
    n >> BigInt(a.width - a.prefix);
}
function forwardedValue(v: string): string {
  if (!v.startsWith('"')) {
    S.need(
      v.length <= 65536 && token(v),
      "node-http",
      "capture",
      "invalid_request",
    );
    return v;
  }
  S.need(v.endsWith('"'), "node-http", "capture", "invalid_request");
  let out = "";
  for (let i = 1; i < v.length - 1; i++) {
    let b = v.charCodeAt(i);
    if (b === 92) {
      b = v.charCodeAt(++i);
      S.need(
        i < v.length - 1 && (b === 9 || b >= 32 && b <= 126),
        "node-http",
        "capture",
        "invalid_request",
      );
    } else {S.need(
        b === 9 || b === 32 || b === 33 || b >= 35 && b <= 91 ||
          b >= 93 && b <= 255,
        "node-http",
        "capture",
        "invalid_request",
      );}
    out += String.fromCharCode(b);
  }
  S.need(out.length > 0, "node-http", "capture", "invalid_request");
  return out;
}
function captureOptions(
  input: unknown,
  keys: readonly string[],
  stage: "attach" | "capture",
) {
  const a = S.take(input, keys, "node-http", stage);
  if (!Object.hasOwn(a, "trustedProxies")) return a;
  const p = S.take(a.trustedProxies, ["peers", "field"], "node-http", stage);
  S.need(
    Array.isArray(p.peers) &&
      p.peers.length > 0 &&
      p.peers.length <= 1024 &&
      (p.field === "forwarded" || p.field === "x-forwarded"),
    "node-http",
    stage,
    "invalid_options",
  );
  const owned = S.unwrap(deepFreeze(p), "node-http", stage, "invalid_options");
  S.need(
    (owned.peers as unknown[]).every((v) => cidr(v)),
    "node-http",
    stage,
    "invalid_options",
  );
  return Object.freeze(
    Object.assign(Object.create(null), a, { trustedProxies: owned }),
  ) as Readonly<Record<string, unknown>>;
}
function origin(
  ingress: Ingress,
  fields: ReturnType<typeof pairs>,
  a: Readonly<Record<string, unknown>>,
) {
  if (!Object.hasOwn(a, "trustedProxies")) {
    return Object.freeze({
      ...normalized(ingress.scheme, ingress.authority),
      source: "connection" as const,
    });
  }
  const p = a.trustedProxies as Readonly<
    { peers: readonly string[]; field: "forwarded" | "x-forwarded" }
  >;
  S.need(
    p.peers.some((v) => contains(v, ingress.remoteAddress)),
    "node-http",
    "capture",
    "untrusted_proxy",
  );
  const values = (name: string) =>
    fields
      .filter((p) => p.name.toLowerCase() === name)
      .map((p) => p.value)
      .join(",");
  let scheme: string | undefined, authority: string | undefined;
  if (p.field === "x-forwarded") {
    const schemes = split(values("x-forwarded-proto"), ","),
      hosts = split(values("x-forwarded-host"), ",");
    S.need(
      schemes.length === hosts.length,
      "node-http",
      "capture",
      "invalid_request",
    );
    scheme = schemes.at(-1);
    authority = hosts.at(-1);
  } else {
    let parsed = Object.create(null) as Record<string, string>;
    for (const element of split(values("forwarded"), ",")) {
      parsed = Object.create(null) as Record<string, string>;
      for (const piece of split(element, ";")) {
        const match = /^([^=]+)=(.*)$/.exec(piece);
        S.need(match, "node-http", "capture", "invalid_request");
        const name = match[1]!.trim().toLowerCase();
        S.need(
          name.length <= 256 && token(name),
          "node-http",
          "capture",
          "invalid_request",
        );
        S.need(
          !Object.hasOwn(parsed, name),
          "node-http",
          "capture",
          "invalid_request",
        );
        parsed[name] = forwardedValue(match[2]!.trim());
      }
    }
    scheme = parsed.proto;
    authority = parsed.host;
  }
  scheme = scheme?.toLowerCase();
  S.need(
    (scheme === "http" || scheme === "https") &&
      typeof authority === "string" &&
      authority.length > 0,
    "node-http",
    "capture",
    "invalid_request",
  );
  return Object.freeze({
    ...normalized(scheme, authority),
    source: "forwarded" as const,
  });
}
async function read(
  req: AsyncIterable<Uint8Array>,
  max: number,
  c: Context,
  exclusive = false,
): Promise<Result<Uint8Array>> {
  const stream = req as Readable;
  let competing = exclusive &&
    (stream.listenerCount("data") > 0 || stream.listenerCount("readable") > 0 ||
      stream.readableFlowing === true);
  let readableListeners = 0;
  const listener = (event: string) => {
    if (event === "data" || event === "readable" && ++readableListeners > 1) {
      competing = true;
    }
  };
  const flowing = () => {
    competing = true;
  };
  if (exclusive) {
    stream.on("newListener", listener);
    stream.on("resume", flowing);
  }
  try {
    return await run(c, async () => {
      const chunks: Uint8Array[] = [];
      let size = 0;
      const close = () => {
        if ("destroy" in req) (req as Readable).destroy();
      };
      c.signal.addEventListener("abort", close, { once: true });
      try {
        for await (const part of req) {
          S.need(
            part instanceof Uint8Array,
            "node-http",
            "capture",
            "body_unavailable",
          );
          S.need(
            !exclusive || !competing && stream.readableFlowing !== true,
            "node-http",
            "capture",
            "parser_order",
          );
          size += part.length;
          S.need(size <= max, "node-http", "capture", "limit");
          chunks.push(new Uint8Array(part));
        }
        S.need(
          !exclusive || !competing && stream.readableFlowing !== true,
          "node-http",
          "capture",
          "parser_order",
        );
        const bytes = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) {
          bytes.set(chunk, offset);
          offset += chunk.length;
        }
        return ok(bytes);
      } catch (e) {
        return S.caught(e, "node-http", "capture", "body_unavailable");
      } finally {
        c.signal.removeEventListener("abort", close);
      }
    });
  } finally {
    if (exclusive) {
      stream.removeListener("newListener", listener);
      stream.removeListener("resume", flowing);
    }
  }
}
function prepare(
  req: Request,
  a: Readonly<Record<string, unknown>>,
  bytes: Uint8Array,
  metadata?: {
    url: string | undefined;
    method: string | undefined;
    rawHeaders: string[];
    originalUrl: unknown;
  },
): Capture {
  const h2 = req instanceof Http2ServerRequest;
  const headers = metadata?.rawHeaders ?? req.rawHeaders.slice();
  const server = (
    req as IncomingMessage & {
      socket: IncomingMessage["socket"] & { server?: Server };
    }
  ).socket.server;
  const maxHeaders = server?.maxHeadersCount;
  S.need(
    !maxHeaders || headers.length / 2 < maxHeaders,
    "node-http",
    "capture",
    "limit",
  );
  const method = metadata?.method ??
    (h2 ? String(req.headers[":method"] ?? req.method) : req.method);
  const original = metadata
    ? metadata.originalUrl
    : (req as Request & { originalUrl?: unknown }).originalUrl;
  const rawTarget = typeof original === "string"
    ? original
    : (metadata?.url ?? req.url);
  S.need(
    typeof method === "string" && method !== "CONNECT" &&
      typeof rawTarget === "string",
    "node-http",
    "capture",
    "invalid_request",
  );
  const tls = req.socket instanceof TLSSocket && req.socket.encrypted;
  S.need(
    headers.filter(
      (name, i) =>
        i % 2 === 0 && name.toLowerCase() === (h2 ? ":authority" : "host"),
    ).length === 1,
    "node-http",
    "capture",
    "invalid_request",
  );
  const hostIndex = headers.findIndex(
    (name, i) =>
      i % 2 === 0 && name.toLowerCase() === (h2 ? ":authority" : "host"),
  );
  const host = hostIndex >= 0 ? headers[hostIndex + 1] : undefined;
  S.need(typeof host === "string", "node-http", "capture", "invalid_request");
  const scheme = tls ? "https" : "http";
  if (h2) {
    const hosts = headers.flatMap((name, i) =>
      i % 2 === 0 && name.toLowerCase() === "host" ? [headers[i + 1]!] : []
    );
    S.need(
      hosts.length <= 1 &&
        hosts.every((v) =>
          normalized(scheme, v).authority === normalized(scheme, host).authority
        ),
      "node-http",
      "capture",
      "invalid_request",
    );
  }
  const ingress: Ingress = Object.freeze({
    evidence: "observed",
    method,
    rawTarget,
    authority: host,
    scheme,
    declaredScheme: h2 ? String(req.headers[":scheme"] ?? "") : null,
    httpVersion: req.httpVersion,
    tls: tls ? "tls" : "plain",
    protocol: tls ? req.socket.getProtocol() : null,
    alpn: tls ? req.socket.alpnProtocol || null : null,
    remoteAddress: req.socket.remoteAddress ?? null,
  });
  const lengths = headers.flatMap((name, i) =>
    i % 2 === 0 && name.toLowerCase() === "content-length"
      ? [headers[i + 1]!]
      : []
  );
  S.need(
    lengths.length <= 1 &&
      (lengths.length === 0 ||
        /^[0-9]+$/.test(lengths[0]!) && Number(lengths[0]) === bytes.length),
    "node-http",
    "capture",
    "body_unavailable",
  );
  const fields = pairs(headers, "headers", h2),
    selected = origin(ingress, fields, a);
  if (h2) {
    S.need(
      (ingress.declaredScheme === "http" ||
        ingress.declaredScheme === "https") &&
        (ingress.declaredScheme === scheme || selected.source === "forwarded"),
      "node-http",
      "capture",
      "invalid_request",
    );
  }
  const message = S.unwrap(
    Message.create({
      kind: "request",
      method,
      rawTarget,
      targetForm: rawTarget === "*"
        ? "asterisk"
        : /^https?:\/\//i.test(rawTarget)
        ? "absolute"
        : "origin",
      scheme: selected.scheme,
      authority: selected.authority,
      fields,
      trailers: pairs(req.rawTrailers, "trailers", h2),
      body: {
        state: "retained",
        bytes,
        maxBytes: S.maximum(a, "node-http", "capture"),
      },
      transport: {
        httpVersion: h2
          ? "http2"
          : req.httpVersion === "1.0"
          ? "http1_0"
          : "http1_1",
        tls: ingress.tls,
      },
    }),
    "node-http",
    "capture",
    "invalid_request",
  );
  const capture: Capture = Object.freeze({
    message,
    ingress,
    origin: selected,
    replay(): Result<Readable> {
      try {
        const state = states.get(req)!;
        S.need(!state.stream, "node-http", "capture", "body_unavailable");
        const data = Buffer.from(bytes);
        let sent = false;
        const stream = new Readable({
          read() {
            if (!sent) {
              sent = true;
              this.push(data);
              this.push(null);
            }
          },
        });
        const originalRead = stream.read;
        stream.read = function (size?: number) {
          const encoding = stream.readableEncoding;
          const chunk: unknown = originalRead.call(this, size);
          state.read = true;
          if (chunk instanceof Uint8Array) state.hash.update(chunk);
          else if (typeof chunk === "string") {
            state.hash.update(Buffer.from(chunk, encoding ?? "utf8"));
          }
          return chunk;
        };
        stream.once("end", () => {
          state.done = true;
        });
        state.stream = stream;
        return ok(stream);
      } catch (e) {
        return S.caught(e, "node-http", "capture", "body_unavailable");
      }
    },
  });
  branded.add(capture);
  states.set(req, {
    capture,
    read: false,
    done: false,
    hash: createHash("sha256"),
  });
  return capture;
}
export async function captureRequest(
  req: unknown,
  options: unknown = {},
): Promise<Result<Capture>> {
  try {
    S.need(
      req instanceof IncomingMessage || req instanceof Http2ServerRequest,
      "node-http",
      "capture",
      "invalid_request",
    );
    const a = captureOptions(
      options,
      ["maxBytes", "context", "trustedProxies", "body"],
      "capture",
    );
    const existing = captures.get(req);
    if (existing) {
      S.need(
        Object.keys(a).length === 0,
        "node-http",
        "capture",
        "invalid_options",
      );
      return await existing;
    }
    const max = S.maximum(a, "node-http", "capture"),
      c = S.context(a, "node-http", "capture");
    // Snapshot ingress before yielding to downstream middleware.
    const metadata = {
      url: req.url,
      method: req.method,
      rawHeaders: req.rawHeaders.slice(),
      originalUrl: (req as Request & { originalUrl?: unknown }).originalUrl,
    };
    const promise = (async (): Promise<Result<Capture>> => {
      try {
        let bytes: Uint8Array;
        if (Object.hasOwn(a, "body")) {
          S.need(
            a.body instanceof Uint8Array && a.body.length <= max,
            "node-http",
            "capture",
            "limit",
          );
          bytes = new Uint8Array(a.body);
        } else {
          S.need(
            !req.readableEnded &&
              !req.destroyed &&
              req.readableFlowing === null,
            "node-http",
            "capture",
            "parser_order",
          );
          bytes = S.unwrap(
            await read(req, max, c, true),
            "node-http",
            "capture",
            "body_unavailable",
          );
        }
        return ok(prepare(req, a, bytes, metadata));
      } catch (e) {
        return S.caught(e, "node-http", "capture", "invalid_request");
      }
    })();
    captures.set(req, promise);
    return await promise;
  } catch (e) {
    return S.caught(e, "node-http", "capture", "invalid_options");
  }
}
export function capture(
  server: unknown,
  options: unknown = {},
): Result<Readonly<{ close: () => Result<true> }>> {
  try {
    const a = captureOptions(
      options,
      ["maxBytes", "context", "trustedProxies"],
      "attach",
    );
    S.maximum(a, "node-http", "attach");
    S.context(a, "node-http", "attach");
    S.need(
      server !== null &&
        typeof server === "object" &&
        "prependListener" in server &&
        typeof server.prependListener === "function" &&
        "removeListener" in server &&
        typeof server.removeListener === "function",
      "node-http",
      "attach",
      "invalid_options",
    );
    const listener = (req: Request) => {
      void captureRequest(req, a);
    };
    server.prependListener("request", listener);
    const close = (): Result<true> => {
      try {
        (server as Server).removeListener("request", listener);
        return ok(true as const);
      } catch (e) {
        return S.caught(e, "node-http", "attach", "invalid_options");
      }
    };
    const registration = Object.freeze({ close });
    registrations.add(registration);
    return ok(registration);
  } catch (e) {
    return S.caught(e, "node-http", "attach", "invalid_options");
  }
}
export function captureBody(
  req: unknown,
  bytes: unknown,
  options: unknown = {},
): Result<Capture> {
  try {
    S.need(
      req instanceof IncomingMessage || req instanceof Http2ServerRequest,
      "node-http",
      "capture",
      "invalid_request",
    );
    S.need(!captures.has(req), "node-http", "capture", "invalid_request");
    const a = captureOptions(
      options,
      ["maxBytes", "trustedProxies"],
      "capture",
    );
    S.need(
      bytes instanceof Uint8Array &&
        bytes.length <= S.maximum(a, "node-http", "capture"),
      "node-http",
      "capture",
      "limit",
    );
    const c = prepare(req, a, new Uint8Array(bytes));
    captures.set(req, Promise.resolve(ok(c)));
    return ok(c);
  } catch (e) {
    return S.caught(e, "node-http", "capture", "invalid_request");
  }
}
function beginVerification(req: object, c: Capture) {
  const state = states.get(req)!;
  S.need(!state.verified, "node-http", "verify", "already_verified");
  if (state.stream) {
    S.need(!state.read || state.done, "node-http", "verify", "parser_order");
    if (state.read) {
      const actual = state.hash.copy().digest(),
        expected = createHash("sha256")
          .update(c.message.body.bytes!)
          .digest();
      S.need(actual.equals(expected), "node-http", "verify", "parser_order");
    }
  }
  // Set attempt state before the async resolver to prevent concurrent verification.
  state.verified = err(S.failure("node-http", "verify", "already_verified"));
  return state;
}
export async function verifyRequest(
  req: unknown,
  policy: unknown,
  options: unknown,
): Promise<Result<VerifiedRequest>> {
  try {
    const a = S.take(
      options,
      ["label", "context", "representation", "digestState"],
      "node-http",
      "verify",
    );
    S.need(
      typeof req === "object" && req !== null && captures.has(req),
      "node-http",
      "verify",
      "not_captured",
    );
    const c = S.unwrap(
      await captures.get(req)!,
      "node-http",
      "verify",
      "request_rejected",
    );
    S.context(a, "node-http", "verify");
    const state = beginVerification(req, c);
    const r = await verify(c.message, policy, a);
    if (!r.ok) {
      const rejected = err<VerifiedRequest>(
        S.failure("node-http", "verify", "request_rejected", r.error),
      );
      state.verified = rejected;
      return rejected;
    }
    const bytes = c.message.body.bytes!;
    const v = Object.freeze({
      capture: c,
      verification: r.value,
      get bytes() {
        return new Uint8Array(bytes);
      },
    });
    verified.add(v);
    const result = ok(v);
    state.verified = result;
    return result;
  } catch (e) {
    const rejected = S.caught<VerifiedRequest>(
      e,
      "node-http",
      "verify",
      "request_rejected",
    );
    return rejected;
  }
}
/** Composite verification over the same captured facts. */
export async function verifyQuorum(
  req: unknown,
  quorum: unknown,
  options: unknown = {},
): Promise<Result<VerifiedQuorumRequest>> {
  try {
    const a = S.take(
      options,
      ["acceptSignature", "context"],
      "node-http",
      "verify",
    );
    S.context(a, "node-http", "verify");
    S.need(
      !Object.hasOwn(a, "acceptSignature") ||
        isAcceptSignature(a.acceptSignature),
      "node-http",
      "verify",
      "invalid_options",
    );
    S.need(
      typeof req === "object" && req !== null && captures.has(req),
      "node-http",
      "verify",
      "not_captured",
    );
    const capture = S.unwrap(
      await captures.get(req)!,
      "node-http",
      "verify",
      "request_rejected",
    );
    const state = beginVerification(req, capture);
    const r = await coreVerifyQuorum(capture.message, quorum, a);
    if (!r.ok) {
      const rejected = err<VerifiedQuorumRequest>(
        S.failure("node-http", "verify", "request_rejected", r.error),
      );
      state.verified = rejected;
      return rejected;
    }
    const bytes = capture.message.body.bytes!;
    const result = Object.freeze({
      capture,
      verification: r.value,
      get bytes() {
        return new Uint8Array(bytes);
      },
    });
    verified.add(result);
    state.verified = ok(result);
    return ok(result);
  } catch (e) {
    const rejected = S.caught<VerifiedQuorumRequest>(
      e,
      "node-http",
      "verify",
      "request_rejected",
    );
    return rejected;
  }
}
/** Web Bot Auth verification over the same captured facts and shared attempt. */
export async function verifyWebBotAuth(
  req: unknown,
  policy: unknown,
  options: unknown = {},
): Promise<Result<VerifiedWebBotAuthRequest>> {
  try {
    const a = S.take(
      options,
      ["context", "timeoutMs", "representation", "digestState"],
      "node-http",
      "verify",
    );
    S.context(a, "node-http", "verify");
    S.need(
      !Object.hasOwn(a, "timeoutMs") ||
        (typeof a.timeoutMs === "number" && Number.isInteger(a.timeoutMs) &&
          a.timeoutMs >= 1 && a.timeoutMs <= 300000),
      "node-http",
      "verify",
      "invalid_options",
    );
    S.need(
      typeof req === "object" && req !== null && captures.has(req),
      "node-http",
      "verify",
      "not_captured",
    );
    const capture = S.unwrap(
      await captures.get(req)!,
      "node-http",
      "verify",
      "request_rejected",
    );
    const state = beginVerification(req, capture);
    const r = await coreVerifyWebBotAuth(capture.message, policy, a);
    if (!r.ok) {
      const rejected = err<VerifiedWebBotAuthRequest>(
        S.failure("node-http", "verify", "request_rejected", r.error),
      );
      state.verified = rejected;
      return rejected;
    }
    const bytes = capture.message.body.bytes!;
    const result = Object.freeze({
      capture,
      verification: r.value,
      get bytes() {
        return new Uint8Array(bytes);
      },
    });
    verified.add(result);
    state.verified = ok(result);
    return ok(result);
  } catch (e) {
    return S.caught<VerifiedWebBotAuthRequest>(
      e,
      "node-http",
      "verify",
      "request_rejected",
    );
  }
}
export function verification(
  req: unknown,
): Result<Verification | QuorumVerification | WebBotAuthVerification> {
  const s = typeof req === "object" && req !== null
    ? states.get(req)
    : undefined;
  return s?.verified?.ok
    ? ok(s.verified.value.verification)
    : s?.verified && !s.verified.ok
    ? s.verified
    : err(S.failure("node-http", "verify", "not_captured"));
}
export async function signResponse(
  res: unknown,
  input: unknown,
  signer: unknown,
  options: unknown = {},
): Promise<Result<HttpMessage>> {
  let previousHeaders: ReturnType<ServerResponse["getHeaders"]> | undefined;
  let response: ServerResponse | Http2ServerResponse | undefined;
  try {
    const a = S.take(
      options,
      ["body", "request", "context", "clock", "nonce", "pendingCookies"],
      "node-http",
      "sign",
    );
    S.need(
      res instanceof ServerResponse || res instanceof Http2ServerResponse,
      "node-http",
      "sign",
      "invalid_request",
    );
    S.need(
      !res.headersSent && !res.writableEnded && res.statusCode >= 200,
      "node-http",
      "sign",
      "unsupported_delivery",
    );
    S.need(
      a.body instanceof Uint8Array,
      "node-http",
      "sign",
      "body_unavailable",
    );
    const bytes = new Uint8Array(a.body),
      s = S.spec(input, "node-http"),
      parts = S.components(s, "node-http");
    S.need(
      !parts.value.some((p) => S.responseRefused(p, S.RESPONSE_HOP_FIELDS)),
      "node-http",
      "sign",
      "unsupported_component",
    );
    S.need(
      !a.pendingCookies ||
        !parts.value.some((p) => p.value.value === "set-cookie"),
      "node-http",
      "sign",
      "unsupported_delivery",
    );
    const c = S.context(a, "node-http", "sign");
    S.need(
      !Object.hasOwn(a, "clock") || typeof a.clock === "function",
      "node-http",
      "sign",
      "invalid_options",
    );
    let now: unknown;
    try {
      now = typeof a.clock === "function"
        ? a.clock()
        : Math.floor(Date.now() / 1000);
    } catch {
      throw S.failure("node-http", "sign", "invalid_options");
    }
    S.need(
      typeof now === "number" && Number.isSafeInteger(now) && now >= 0 &&
        Number.isFinite(new Date(now * 1000).getTime()),
      "node-http",
      "sign",
      "invalid_options",
    );
    const fixedOptions = Object.assign(Object.create(null), a, {
      clock: () => now,
    });
    previousHeaders = res.getHeaders();
    response = res;
    res.setHeader("Date", new Date(now * 1000).toUTCString());
    const noBody = res.statusCode === 204 ||
      res.statusCode === 304;
    S.need(
      !noBody || bytes.length === 0,
      "node-http",
      "sign",
      "unsupported_delivery",
    );
    if (noBody) res.removeHeader("Content-Length");
    else res.setHeader("Content-Length", bytes.length);
    const fields: {
      name: FieldOccurrence["name"];
      value: string;
      section: FieldOccurrence["section"];
    }[] = [];
    for (const [name, v] of Object.entries(res.getHeaders())) {
      for (const item of Array.isArray(v) ? v : [v]) {
        fields.push({ name, value: String(item), section: "headers" });
      }
    }
    const request = Object.hasOwn(a, "request") ? a.request : null;
    S.need(
      request === null ||
        (typeof request === "object" &&
          request !== null &&
          branded.has(request)),
      "node-http",
      "sign",
      "invalid_options",
    );
    const m = S.unwrap(
      Message.create({
        kind: "response",
        status: res.statusCode,
        fields,
        trailers: "unavailable",
        body: { state: "retained", bytes },
        transport: {},
        relatedRequest: request === null ? null : (request as Capture).message,
      }),
      "node-http",
      "sign",
      "invalid_request",
    );
    const signed = S.unwrap(
      await sign(m, s, signer, S.signingOptions(fixedOptions, c)),
      "node-http",
      "sign",
      "signing_failed",
    );
    const grouped = new Map<string, string[]>();
    for (const f of signed.fields) {
      const name = f.name.toLowerCase();
      const list = grouped.get(name) ?? [];
      list.push(S.latin(f.value));
      grouped.set(name, list);
    }
    for (const [name, list] of grouped) {
      res.setHeader(name, list.length === 1 ? list[0]! : list);
    }
    const finalResponse: { writeHead(statusCode: number): unknown } = res;
    finalResponse.writeHead(res.statusCode);
    res.end(bytes);
    return ok(signed);
  } catch (e) {
    if (response && previousHeaders && !response.headersSent) {
      for (const name of response.getHeaderNames()) response.removeHeader(name);
      for (const [name, value] of Object.entries(previousHeaders)) {
        if (value !== undefined) response.setHeader(name, value);
      }
    }
    return S.caught(e, "node-http", "sign", "signing_failed");
  }
}
export async function verifyResponse(
  response: unknown,
  request: unknown,
  policy: unknown,
  options: unknown,
): Promise<
  Result<
    Readonly<{
      message: HttpMessage;
      verification: Verification;
      bytes: Uint8Array;
    }>
  >
> {
  try {
    S.need(
      typeof response === "object" &&
        response !== null &&
        clientResponses.has(response),
      "node-http",
      "verify",
      "invalid_request",
    );
    const r = response as ClientResponse;
    S.need(request === r.request, "node-http", "verify", "invalid_request");
    const a = S.take(
      options,
      ["label", "context", "representation", "digestState"],
      "node-http",
      "verify",
    );
    const v = S.unwrap(
      await verify(r.message, policy, a),
      "node-http",
      "verify",
      "response_rejected",
    );
    const bytes = r.bytes;
    return ok(
      Object.freeze({
        message: r.message,
        verification: v,
        get bytes() {
          return new Uint8Array(bytes);
        },
      }),
    );
  } catch (e) {
    return S.caught(e, "node-http", "verify", "response_rejected");
  }
}
async function send(
  url: URL,
  m: HttpMessage,
  body: Uint8Array,
  a: Readonly<Record<string, unknown>>,
  c: Context,
  attempt: number,
): Promise<Result<ClientResponse>> {
  return run(
    c,
    () =>
      new Promise((resolve) => {
        let settled = false;
        const done = (r: Result<ClientResponse>) => {
          if (settled) return;
          settled = true;
          c.signal.removeEventListener("abort", abort);
          resolve(r);
        };
        const headers = m.fields.flatMap((f) => [f.name, S.latin(f.value)]);
        if (!m.fields.some((f) => f.name.toLowerCase() === "host")) {
          headers.push("Host", url.host);
        }
        if (
          m.method !== "GET" && m.method !== "HEAD" &&
          !m.fields.some((f) => f.name.toLowerCase() === "content-length")
        ) {
          headers.push("Content-Length", String(body.length));
        }
        const opts = {
          path: m.rawTarget!,
          method: m.method!,
          headers,
          agent: false as const,
          ...(a.ca instanceof Uint8Array ? { ca: Buffer.from(a.ca) } : {}),
        };
        const req = (url.protocol === "https:" ? httpsRequest : httpRequest)(
          url,
          opts,
          async (res) => {
            try {
              const bytes = S.unwrap(
                await read(res, S.maximum(a, "node-http", "verify"), c),
                "node-http",
                "verify",
                "body_unavailable",
                attempt,
              );
              const message = S.unwrap(
                Message.create({
                  kind: "response",
                  status: res.statusCode,
                  fields: pairs(res.rawHeaders, "headers", false),
                  trailers: pairs(res.rawTrailers, "trailers", false),
                  body: { state: "retained", bytes },
                  relatedRequest: m,
                  transport: {
                    httpVersion: "http1_1",
                    tls: url.protocol === "https:" ? "tls" : "plain",
                  },
                }),
                "node-http",
                "verify",
                "invalid_request",
                attempt,
              );
              const result = Object.freeze({
                request: m,
                message,
                status: res.statusCode!,
                get bytes() {
                  return new Uint8Array(bytes);
                },
              });
              clientResponses.add(result);
              done(ok(result));
            } catch (e) {
              done(
                S.caught(
                  e,
                  "node-http",
                  "verify",
                  "response_rejected",
                  attempt,
                ),
              );
            }
          },
        );
        const abort = () => {
          req.destroy();
          done(
            err(
              S.failure("node-http", "sign", "body_unavailable", null, attempt),
            ),
          );
        };
        c.signal.addEventListener("abort", abort, { once: true });
        req.once(
          "error",
          () =>
            done(
              err(
                S.failure(
                  "node-http",
                  "sign",
                  "invalid_request",
                  null,
                  attempt,
                ),
              ),
            ),
        );
        req.end(body);
      }),
  );
}
export async function signedRequest(
  options: unknown,
  input: unknown,
  signer: unknown,
  ctx?: Context,
): Promise<Result<ClientResponse>> {
  let attempt = 0;
  try {
    const a = S.redirectOptions(
      S.take(
        options,
        [
          "url",
          "method",
          "headers",
          "body",
          "ca",
          "context",
          "clock",
          "nonce",
          "maxBytes",
          "maxRedirects",
          "maxRetries",
          "allowedOrigins",
          "credentialHeaders",
          "verify",
        ],
        "node-http",
        "attach",
      ),
      "node-http",
    );
    S.need(
      !Object.hasOwn(a, "ca") || a.ca instanceof Uint8Array,
      "node-http",
      "attach",
      "invalid_options",
    );
    const ca = a.ca instanceof Uint8Array ? new Uint8Array(a.ca) : undefined;
    const transportOptions = Object.assign(Object.create(null), a, { ca });
    const c = S.context(
      ctx === undefined ? a : { ...a, context: ctx },
      "node-http",
      "attach",
    );
    const s = S.spec(input, "node-http");
    S.need(typeof a.url === "string", "node-http", "attach", "invalid_options");
    let url = new URL(a.url);
    S.need(
      ["http:", "https:"].includes(url.protocol) &&
        !url.hash &&
        !url.username &&
        !url.password,
      "node-http",
      "attach",
      "invalid_request",
    );
    const suppliedMethod = a.method === undefined ? "GET" : a.method;
    S.need(
      typeof suppliedMethod === "string",
      "node-http",
      "attach",
      "invalid_options",
    );
    S.need(token(suppliedMethod), "node-http", "attach", "invalid_request");
    // ClientRequest uppercases its method before delivery; sign those final bytes.
    let method = suppliedMethod.toUpperCase();
    const source = new URL(url);
    const suppliedBody = a.body === undefined ? new Uint8Array() : a.body;
    S.need(
      suppliedBody instanceof Uint8Array,
      "node-http",
      "attach",
      "body_unavailable",
    );
    let body = new Uint8Array(suppliedBody);
    S.need(
      !["GET", "HEAD"].includes(method) || body.length === 0,
      "node-http",
      "attach",
      "invalid_options",
    );
    S.need(
      body instanceof Uint8Array &&
        body.length <= S.maximum(a, "node-http", "attach"),
      "node-http",
      "attach",
      "body_unavailable",
    );
    let fields = a.headers === undefined ? [] : a.headers;
    S.need(
      Array.isArray(fields) &&
        fields.every(
          (p) =>
            Array.isArray(p) &&
            p.length === 2 &&
            typeof p[0] === "string" &&
            typeof p[1] === "string",
        ),
      "node-http",
      "attach",
      "invalid_options",
    );
    S.need(
      !(fields as [string, string][]).some(([name]) =>
        name.toLowerCase() === "host"
      ),
      "node-http",
      "attach",
      "invalid_options",
    );
    fields = (fields as [string, string][]).map((p) => [...p]);
    const redirects = S.limitNumber(a.maxRedirects ?? 0, 10, "node-http"),
      retries = S.limitNumber(a.maxRetries ?? 0, 10, "node-http");
    let hops = 0, retry = 0;
    for (;;) {
      attempt++;
      const m = S.unwrap(
        await Message.request(method, url.href, fields, body),
        "node-http",
        "sign",
        "invalid_request",
        attempt,
      );
      const signed = S.unwrap(
        await sign(
          m,
          s,
          signer,
          S.signingOptions(
            attempt === 1 ? a : Object.fromEntries(
              Object.entries(a).filter(([k]) => k !== "nonce"),
            ),
            c,
          ),
        ),
        "node-http",
        "sign",
        "signing_failed",
        attempt,
      );
      const response = await send(
        url,
        signed,
        body,
        transportOptions,
        c,
        attempt,
      );
      if (!response.ok) return response;
      if (a.verify !== undefined) {
        const v = S.take(a.verify, ["policy", "label"], "node-http", "verify");
        S.need(isPolicy(v.policy), "node-http", "verify", "invalid_options");
        const verified = await verifyResponse(
          response.value,
          signed,
          v.policy,
          { label: v.label, context: c },
        );
        if (!verified.ok) {
          return S.caught(
            verified.error,
            "node-http",
            "verify",
            "response_rejected",
            attempt,
          );
        }
      }
      const status = response.value.status;
      if ([301, 302, 303, 307, 308].includes(status) && hops < redirects) {
        const location = response.value.message.fields.find(
          (f) => f.name.toLowerCase() === "location",
        );
        S.need(location, "node-http", "sign", "invalid_request", attempt);
        const next = S.redirectLocation(
          S.latin(location.value),
          url,
          "node-http",
          attempt,
        );
        S.allowedOrigin(next, source, a.allowedOrigins, "node-http", attempt);
        if (next.origin !== url.origin) {
          const extra = a.credentialHeaders ?? [];
          S.need(
            Array.isArray(extra) &&
              extra.length <= 64 &&
              extra.every((v) => typeof v === "string"),
            "node-http",
            "sign",
            "invalid_options",
          );
          const strip = [
            "authorization",
            "cookie",
            "proxy-authorization",
            ...(extra as string[]),
          ].map((v) => v.toLowerCase());
          fields = (fields as [string, string][]).filter(
            (p) => !strip.includes(p[0].toLowerCase()),
          );
        }
        if (S.redirectGet(status, method)) {
          method = "GET";
          body = new Uint8Array();
          fields = (fields as [string, string][]).filter((p) =>
            !S.REDIRECT_BODY_FIELDS.includes(p[0].toLowerCase())
          );
        }
        url = next;
        hops++;
        continue;
      }
      if (status >= 500 && retry < retries) {
        retry++;
        continue;
      }
      return response;
    }
  } catch (e) {
    return S.caught(e, "node-http", "sign", "signing_failed", attempt);
  }
}
