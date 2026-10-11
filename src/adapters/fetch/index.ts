import {
  isMessage,
  Message,
  type Message as HttpMessage,
} from "../../message/index.ts";
import { sign } from "../../sign.ts";
import { verify } from "../../verify.ts";
import { isPolicy, type Policy } from "../../policy.ts";
import type { Verification } from "../../verification.ts";
import { type Context, run, withDeadline } from "../../context.ts";
import { TIMEOUT_MAX_MS } from "../../constants.ts";
import { dictionaries, inner } from "../../signature-fields.ts";
import { err, ok, type Result } from "../../result.ts";
import { canVerify, runtime, signingRefusals } from "./runtime.ts";
import * as S from "../support.ts";
export { FETCH_VERIFICATION_RUNTIMES } from "./runtime.ts";
export type SignedRequest = Readonly<{
  request: Request;
  message: HttpMessage;
}>;
export type SignedResponse = Readonly<{
  response: Response;
  message: HttpMessage;
}>;
export type VerifiedRequest = Readonly<{
  request: Request;
  message: HttpMessage;
  verification: Verification;
  bytes: Uint8Array;
}>;
export type VerifiedResponse = Readonly<{
  response: Response;
  message: HttpMessage;
  verification: Verification;
  bytes: Uint8Array;
}>;
export type SignedExchange = Readonly<{
  response: Response;
  request: SignedRequest;
}>;
const signedExchanges = new WeakSet<object>();
const signedRequests = new WeakSet<object>(),
  signedResponses = new WeakSet<object>(),
  verifiedRequests = new WeakSet<object>(),
  verifiedResponses = new WeakSet<object>();
const fetchCall = globalThis.fetch.bind(globalThis);
function requestContext(parent: Context, signal: AbortSignal): Context {
  return S.unwrap(
    withDeadline({ parent, signal, timeoutMs: TIMEOUT_MAX_MS }),
    "fetch",
    "attach",
    "invalid_options",
  );
}
function pairs(headers: Headers): [string, string][] {
  const out: [string, string][] = [];
  headers.forEach((value, name) => {
    if (name !== "set-cookie") out.push([name, value]);
  });
  const cookies = headers.getSetCookie();
  for (const cookie of cookies) out.push(["set-cookie", cookie]);
  return out;
}
function headers(message: HttpMessage): Headers {
  const h = new Headers();
  for (const f of message.fields) h.append(f.name, S.latin(f.value));
  return h;
}
// Captured once: a runtime without this accessor cannot carry Request streams.
const requestBodyAccessor = typeof Request === "function"
  ? Object.getOwnPropertyDescriptor(Request.prototype, "body")
  : undefined;
function requestBodySupported(
  request: Request,
  stage: "sign" | "verify",
): void {
  // Native ingress can omit GET/HEAD bodies while retaining their declared length.
  S.need(
    !["GET", "HEAD"].includes(request.method.toUpperCase()) ||
      (request.body == null &&
        !(Number(request.headers.get("content-length")) > 0)),
    "fetch",
    stage,
    "invalid_request",
  );
}
async function bytes(
  value: Request | Response,
  max: number,
  c: Context,
  stage: "sign" | "verify",
): Promise<Result<Uint8Array>> {
  return run(c, async () => {
    try {
      S.need(!value.bodyUsed, "fetch", stage, "body_unavailable");
      if (value.body === null) return ok(new Uint8Array());
      if (value instanceof Request && requestBodyAccessor === undefined) {
        // Runtimes without the body accessor cannot accept Request streams.
        // The input is already materialized; this read allocates a complete copy
        // before maxBytes can bound the bytes accepted for signing.
        const data = new Uint8Array(await value.clone().arrayBuffer());
        S.need(data.length <= max, "fetch", stage, "limit");
        return ok(data);
      }
      const reader = value.body.getReader();
      const cancel = () => {
        void reader.cancel().catch(() => {});
      };
      c.signal.addEventListener("abort", cancel, { once: true });
      let complete = false;
      try {
        const parts: Uint8Array[] = [];
        let size = 0;
        for (;;) {
          const next = await reader.read();
          if (next.done) {
            complete = true;
            break;
          }
          S.need(
            next.value instanceof Uint8Array,
            "fetch",
            stage,
            "body_unavailable",
          );
          size += next.value.length;
          S.need(size <= max, "fetch", stage, "limit");
          parts.push(new Uint8Array(next.value));
        }
        const result = new Uint8Array(size);
        let offset = 0;
        for (const part of parts) {
          result.set(part, offset);
          offset += part.length;
        }
        return ok(result);
      } finally {
        if (!complete) await reader.cancel().catch(() => {});
        reader.releaseLock();
        c.signal.removeEventListener("abort", cancel);
      }
    } catch (e) {
      return S.caught(e, "fetch", stage, "body_unavailable");
    }
  });
}
function rebuildRequest(
  source: Request,
  url: string,
  fields: Headers,
  data: Uint8Array,
  c: Context,
  method = source.method,
): Request {
  return new Request(url, {
    method,
    headers: fields,
    ...(method === "GET" || method === "HEAD"
      ? {}
      : { body: new Uint8Array(data) }),
    redirect: "manual",
    credentials: source.credentials,
    mode: source.mode,
    cache: source.cache,
    referrer: source.referrer,
    referrerPolicy: source.referrerPolicy,
    integrity: source.integrity,
    keepalive: source.keepalive,
    signal: c.signal,
  });
}
function rebuildResponse(
  source: Response,
  fields: Headers,
  data: Uint8Array,
): Response {
  return new Response(
    [101, 204, 205, 304].includes(source.status) ? null : new Uint8Array(data),
    { status: source.status, statusText: source.statusText, headers: fields },
  );
}
function signSupported(
  s: Readonly<Record<string, unknown>>,
  response = false,
): void {
  const parts = S.components(s, "fetch");
  S.need(
    !parts.value.some(
      (item) =>
        response
          ? S.responseRefused(item, signingRefusals)
          : signingRefusals.includes(String(item.value.value)) ||
            item.parameters.some(([k]) => k === "tr"),
    ),
    "fetch",
    "sign",
    "unsupported_component",
  );
}
function verifySupported(
  message: HttpMessage,
  policy: Policy,
  label: unknown,
): void {
  const unsupported = (list: ReturnType<typeof inner>) =>
    list.ok &&
    list.value.value.some(
      (item) =>
        [
          "@request-target",
          "@target-uri",
          "@path",
          "@query",
          "cookie",
        ].includes(String(item.value.value)) ||
        item.parameters.some(([k]) => k === "bs" || k === "tr"),
    );
  S.need(
    !unsupported(ok(policy.components)),
    "fetch",
    "verify",
    "unsupported_component",
  );
  try {
    const [inputs] = dictionaries(message, policy.maxSignatures);
    const selected = inputs.get(String(label));
    if (selected) {
      S.need(
        !unsupported(ok(selected)),
        "fetch",
        "verify",
        "unsupported_component",
      );
    }
  } catch (e) {
    if (e && typeof e === "object" && "kind" in e && e.kind === "adapter") {
      throw e;
    }
  }
}
export async function signRequest(
  request: unknown,
  input: unknown,
  signer: unknown,
  options: unknown = {},
): Promise<Result<SignedRequest>> {
  return signRequestOperation(request, input, signer, options);
}
async function signRequestOperation(
  request: unknown,
  input: unknown,
  signer: unknown,
  options: unknown,
  exchangeContext?: Context,
): Promise<Result<SignedRequest>> {
  try {
    const a = S.take(
      options,
      ["context", "maxBytes", "clock", "nonce", "signingTimeout"],
      "fetch",
      "sign",
    );
    S.need(request instanceof Request, "fetch", "sign", "invalid_request");
    S.need(
      !runtime.startsWith("bun:") ||
        !new URL(request.url).pathname.startsWith("//"),
      "fetch",
      "sign",
      "invalid_request",
    );
    // Node majors below 24 do not preserve an empty query delimiter in delivery.
    const finalUrl = new URL(request.url);
    finalUrl.hash = "";
    S.need(
      !(runtime.startsWith("node:") &&
        Number(runtime.slice(5).split(".")[0]) < 24) ||
        !finalUrl.href.endsWith("?"),
      "fetch",
      "sign",
      "invalid_request",
    );
    requestBodySupported(request, "sign");
    const s = S.spec(input, "fetch");
    signSupported(s);
    S.need(
      !runtime.startsWith("bun:") ||
        ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].includes(
          request.method,
        ),
      "fetch",
      "sign",
      "invalid_request",
    );
    const c = exchangeContext ??
        requestContext(S.context(a, "fetch", "sign"), request.signal),
      data = S.unwrap(
        await bytes(request, S.maximum(a, "fetch", "sign"), c, "sign"),
        "fetch",
        "sign",
        "body_unavailable",
      );
    const url = new URL(request.url);
    url.hash = "";
    const m = S.unwrap(
      await Message.request(
        request.method,
        url.href,
        pairs(request.headers),
        data,
      ),
      "fetch",
      "sign",
      "invalid_request",
    );
    const signed = S.unwrap(
      await sign(m, s, signer, S.signingOptions(a, c)),
      "fetch",
      "sign",
      "signing_failed",
    );
    const result = Object.freeze({
      message: signed,
      request: rebuildRequest(request, url.href, headers(signed), data, c),
    });
    signedRequests.add(result);
    return ok(result);
  } catch (e) {
    return S.caught(e, "fetch", "sign", "signing_failed");
  }
}
export async function signResponse(
  response: unknown,
  input: unknown,
  signer: unknown,
  options: unknown = {},
): Promise<Result<SignedResponse>> {
  try {
    const a = S.take(
      options,
      ["context", "maxBytes", "request", "clock", "nonce", "signingTimeout"],
      "fetch",
      "sign",
    );
    S.need(response instanceof Response, "fetch", "sign", "invalid_request");
    const s = S.spec(input, "fetch");
    signSupported(s, true);
    const c = S.context(a, "fetch", "sign"),
      data = S.unwrap(
        await bytes(response, S.maximum(a, "fetch", "sign"), c, "sign"),
        "fetch",
        "sign",
        "body_unavailable",
      );
    const request = related(a.request, "sign");
    const m = S.unwrap(
      await Message.response(response.status, pairs(response.headers), data, {
        request,
      }),
      "fetch",
      "sign",
      "invalid_request",
    );
    const signed = S.unwrap(
      await sign(m, s, signer, S.signingOptions(a, c)),
      "fetch",
      "sign",
      "signing_failed",
    );
    const result = Object.freeze({
      message: signed,
      response: rebuildResponse(response, headers(signed), data),
    });
    signedResponses.add(result);
    return ok(result);
  } catch (e) {
    return S.caught(e, "fetch", "sign", "signing_failed");
  }
}
function related(
  value: unknown,
  stage: "sign" | "verify" = "verify",
): HttpMessage | null {
  if (value === undefined) return null;
  if (isMessage(value) && value.kind === "request") return value;
  if (
    typeof value === "object" && value !== null && signedRequests.has(value)
  ) {
    return (value as SignedRequest).message;
  }
  throw S.failure("fetch", stage, "invalid_options");
}
export async function verifyRequest(
  request: unknown,
  policy: unknown,
  options: unknown,
): Promise<Result<VerifiedRequest>> {
  // This guard precedes all option access, stream reads, clocks, and resolvers.
  if (!canVerify) return err(S.failure("fetch", "verify", "invalid_request"));
  try {
    const a = S.take(
      options,
      ["label", "scheme", "authority", "context", "maxBytes", "representation"],
      "fetch",
      "verify",
    );
    S.need(
      typeof a.label === "string" && /^[a-z*][a-z0-9_.*-]{0,63}$/.test(a.label),
      "fetch",
      "verify",
      "invalid_options",
    );
    S.need(
      request instanceof Request && isPolicy(policy),
      "fetch",
      "verify",
      "invalid_options",
    );
    S.need(
      (a.scheme === "http" || a.scheme === "https") &&
        typeof a.authority === "string",
      "fetch",
      "verify",
      "invalid_options",
    );
    requestBodySupported(request, "verify");
    S.need(
      policy.content === "not_required" ||
        !request.headers.has("content-encoding"),
      "fetch",
      "verify",
      "body_unavailable",
    );
    const c = requestContext(S.context(a, "fetch", "verify"), request.signal);
    const url = new URL(request.url);
    url.hash = "";
    const before = S.unwrap(
      await Message.request(
        request.method,
        url.href,
        pairs(request.headers),
        new Uint8Array(),
      ),
      "fetch",
      "verify",
      "invalid_request",
    );
    const skeleton = S.unwrap(
      Message.create({ ...before, scheme: a.scheme, authority: a.authority }),
      "fetch",
      "verify",
      "invalid_request",
    );
    verifySupported(skeleton, policy, a.label);
    const data = S.unwrap(
      await bytes(request, S.maximum(a, "fetch", "verify"), c, "verify"),
      "fetch",
      "verify",
      "body_unavailable",
    );
    const message = S.unwrap(
      Message.create({ ...skeleton, body: { state: "retained", bytes: data } }),
      "fetch",
      "verify",
      "invalid_request",
    );
    const opts = Object.assign(
      Object.create(null),
      { label: a.label, context: c },
      Object.hasOwn(a, "representation")
        ? { representation: a.representation }
        : {},
    );
    const v = S.unwrap(
      await verify(message, policy, opts),
      "fetch",
      "verify",
      "request_rejected",
    );
    const result = Object.freeze({
      request: rebuildRequest(request, url.href, request.headers, data, c),
      message,
      verification: v,
      get bytes() {
        return new Uint8Array(data);
      },
    });
    verifiedRequests.add(result);
    return ok(result);
  } catch (e) {
    return S.caught(e, "fetch", "verify", "request_rejected");
  }
}
export async function verifyResponse(
  response: unknown,
  policy: unknown,
  options: unknown,
): Promise<Result<VerifiedResponse>> {
  if (!canVerify) return err(S.failure("fetch", "verify", "invalid_request"));
  try {
    const a = S.take(
      options,
      ["label", "request", "context", "maxBytes"],
      "fetch",
      "verify",
    );
    S.need(
      typeof a.label === "string" && /^[a-z*][a-z0-9_.*-]{0,63}$/.test(a.label),
      "fetch",
      "verify",
      "invalid_options",
    );
    S.need(
      response instanceof Response && isPolicy(policy),
      "fetch",
      "verify",
      "invalid_options",
    );
    // The proven Deno fetch lane strips Content-Encoding after decoding. Response
    // content checks cannot establish wire-body identity even when the header is absent.
    S.need(
      policy.content === "not_required",
      "fetch",
      "verify",
      "body_unavailable",
    );
    const request = related(a.request),
      c = S.context(a, "fetch", "verify");
    const skeleton = S.unwrap(
      await Message.response(
        response.status,
        pairs(response.headers),
        new Uint8Array(),
        { request },
      ),
      "fetch",
      "verify",
      "invalid_request",
    );
    verifySupported(skeleton, policy, a.label);
    const data = S.unwrap(
      await bytes(response, S.maximum(a, "fetch", "verify"), c, "verify"),
      "fetch",
      "verify",
      "body_unavailable",
    );
    const message = S.unwrap(
      Message.create({ ...skeleton, body: { state: "retained", bytes: data } }),
      "fetch",
      "verify",
      "invalid_request",
    );
    const v = S.unwrap(
      await verify(message, policy, { label: a.label, context: c }),
      "fetch",
      "verify",
      "response_rejected",
    );
    const result = Object.freeze({
      response: rebuildResponse(response, response.headers, data),
      message,
      verification: v,
      get bytes() {
        return new Uint8Array(data);
      },
    });
    verifiedResponses.add(result);
    return ok(result);
  } catch (e) {
    return S.caught(e, "fetch", "verify", "response_rejected");
  }
}
export async function signedFetch(
  input: unknown,
  init: unknown,
  signing: unknown,
  options: unknown = {},
): Promise<Result<SignedExchange>> {
  let attempt = 0;
  try {
    const a = S.redirectOptions(
      S.take(
        options,
        [
          "context",
          "maxBytes",
          "maxRedirects",
          "maxRetries",
          "allowedOrigins",
          "credentialHeaders",
          "verify",
          "clock",
          "nonce",
          "signingTimeout",
        ],
        "fetch",
        "attach",
      ),
      "fetch",
    );
    const config = S.take(signing, ["spec", "signer"], "fetch", "attach");
    const s = S.spec(config.spec, "fetch");
    signSupported(s);
    const i = S.take(
      init ?? {},
      [
        "method",
        "headers",
        "body",
        "credentials",
        "cache",
        "mode",
        "referrer",
        "referrerPolicy",
        "integrity",
        "keepalive",
        "signal",
      ],
      "fetch",
      "attach",
    );
    const parent = S.context(a, "fetch", "attach");
    S.need(
      typeof input === "string" ||
        input instanceof URL ||
        input instanceof Request,
      "fetch",
      "attach",
      "invalid_request",
    );
    if (a.verify !== undefined) {
      S.need(canVerify, "fetch", "verify", "invalid_request");
    }
    // Constructing from another Request resets referrerPolicy unless explicit.
    const initialOptions = input instanceof Request &&
        !Object.hasOwn(i, "referrerPolicy")
      ? Object.assign(Object.create(null), i, {
        referrerPolicy: input.referrerPolicy,
      })
      : i;
    let current = input instanceof Request && Object.keys(i).length === 0
      ? input
      : new Request(input, initialOptions as RequestInit);
    const callerSignal = i.signal instanceof AbortSignal
      ? i.signal
      : Object.hasOwn(i, "signal")
      ? current.signal
      : input instanceof Request
      ? input.signal
      : current.signal;
    const c = requestContext(parent, callerSignal);
    S.need(!current.headers.has("host"), "fetch", "attach", "invalid_options");
    S.need(
      !current.headers.has("accept-encoding") ||
        current.headers.get("accept-encoding") === "identity",
      "fetch",
      "attach",
      "invalid_options",
    );
    const original = new URL(current.url);
    S.need(
      ["http:", "https:"].includes(original.protocol) &&
        !original.username &&
        !original.password,
      "fetch",
      "attach",
      "invalid_request",
    );
    let data = S.unwrap(
      await bytes(current, S.maximum(a, "fetch", "attach"), c, "sign"),
      "fetch",
      "attach",
      "body_unavailable",
    );
    const maxRedirects = S.limitNumber(a.maxRedirects ?? 0, 10, "fetch"),
      maxRetries = S.limitNumber(a.maxRetries ?? 0, 10, "fetch");
    let redirects = 0, retries = 0;
    for (;;) {
      attempt++;
      const h = new Headers(current.headers);
      h.set("accept-encoding", "identity");
      if (!current.bodyUsed) await current.body?.cancel();
      current = rebuildRequest(current, current.url, h, data, c);
      const signingOpts = Object.assign(Object.create(null), {
        context: c,
        maxBytes: S.maximum(a, "fetch", "sign"),
      });
      for (const k of ["clock", "signingTimeout"]) {
        if (Object.hasOwn(a, k)) signingOpts[k] = a[k];
      }
      if (attempt === 1 && Object.hasOwn(a, "nonce")) {
        signingOpts.nonce = a.nonce;
      }
      const signed = S.unwrap(
        await signRequestOperation(current, s, config.signer, signingOpts, c),
        "fetch",
        "sign",
        "signing_failed",
        attempt,
      );
      const received = await run(c, async () => {
        try {
          return ok(
            await fetchCall(signed.request, {
              redirect: "manual",
              signal: c.signal,
            }),
          );
        } catch {
          return err(
            S.failure("fetch", "sign", "invalid_request", null, attempt),
          );
        }
      });
      if (!received.ok) return received;
      let response = received.value;
      if (a.verify !== undefined) {
        const v = S.take(a.verify, ["policy", "label"], "fetch", "verify");
        const r = await verifyResponse(response, v.policy, {
          label: v.label,
          request: signed,
          context: c,
          maxBytes: S.maximum(a, "fetch", "verify"),
        });
        if (!r.ok) {
          return S.caught(
            r.error,
            "fetch",
            "verify",
            "response_rejected",
            attempt,
          );
        }
        response = r.value.response;
      }
      if (
        [301, 302, 303, 307, 308].includes(response.status) &&
        redirects < maxRedirects
      ) {
        const location = response.headers.get("location");
        S.need(location !== null, "fetch", "sign", "invalid_request", attempt);
        const next = S.redirectLocation(
          location,
          current.url,
          "fetch",
          attempt,
        );
        S.allowedOrigin(next, original, a.allowedOrigins, "fetch", attempt);
        const fields = new Headers(current.headers);
        if (next.origin !== new URL(current.url).origin) {
          const extra = a.credentialHeaders ?? [];
          S.need(
            Array.isArray(extra) &&
              extra.length <= 64 &&
              extra.every((k) => typeof k === "string"),
            "fetch",
            "sign",
            "invalid_options",
          );
          for (
            const name of [
              "authorization",
              "cookie",
              "proxy-authorization",
              ...(extra as string[]),
            ]
          ) {
            fields.delete(name);
          }
        }
        await response.body?.cancel();
        if (S.redirectGet(response.status, current.method)) {
          data = new Uint8Array();
          for (const name of S.REDIRECT_BODY_FIELDS) fields.delete(name);
          current = rebuildRequest(current, next.href, fields, data, c, "GET");
        } else current = rebuildRequest(current, next.href, fields, data, c);
        redirects++;
        continue;
      }
      if (response.status >= 500 && retries < maxRetries) {
        await response.body?.cancel();
        retries++;
        continue;
      }
      const exchange = Object.freeze({ response, request: signed });
      signedExchanges.add(exchange);
      return ok(exchange);
    }
  } catch (e) {
    return S.caught(e, "fetch", "sign", "signing_failed", attempt);
  }
}
