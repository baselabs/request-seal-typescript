import { Agent, request } from "node:https";
import type { IncomingMessage } from "node:http";
import { promises as dns } from "node:dns";
import { isIP } from "node:net";
import * as tls from "node:tls";
import { connect, checkServerIdentity, type TLSSocket } from "node:tls";
import { err, type Result } from "../result.ts";
import {
  withDeadline,
  isContext,
  run,
  remainingMs,
  type Context,
} from "../context.ts";
import { discoveryError, custodyError } from "../errors/types.ts";
import { encodeBase64 } from "../bytes.ts";
import { Discovery as CoreDiscovery } from "./index.ts";
import {
  sourceUrl,
  normalizedHost,
  sourceAuthority,
  sourceOrigin,
  isDiscoverySource,
  DiscoverySource as CoreSource,
} from "./source.ts";
import { addressAllowed } from "./address.ts";
import {
  ensure,
  unwrap,
  failure,
  options,
  clockValue,
  systemClock,
  sslError,
  list,
} from "./support.ts";
import { fields, header, expiry, mediaType } from "./headers.ts";
import { bodyDocument, type KeySet } from "./body.ts";
import { fromResource } from "./snapshot.ts";
import { decodeBody } from "./gzip.ts";
import {systemCertificateError} from "./node-trust.ts";
import { checkPeer, allowConnectionRetry } from "./node-connection.ts";
const lookup = dns.lookup.bind(dns);
export type DiscoverySource = import("./source.ts").DiscoverySource;
type Resource = {
  fields: ReturnType<typeof fields>;
  encoded: Uint8Array;
  decoded: Uint8Array;
  location: string;
};
function remaining(context: Context): void {
  ensure(remainingMs(context) > 0, "deadline_exceeded");
}

async function resolve(
  host: string,
  context: Context,
  servers?: readonly string[],
): Promise<string[]> {
  remaining(context);
  if (isIP(host)) return [host];
  let answers: { address: string; family: number }[];
  if (servers) {
    // An explicit independent DNS resolver never changes process/OS configuration.
    const resolver = new dns.Resolver({
      timeout: Math.ceil(remainingMs(context)),
      tries: 1,
    });
    resolver.setServers([...servers]);
    const cancel = () => resolver.cancel();
    context.signal.addEventListener("abort", cancel, { once: true });
    try {
      const found = await Promise.allSettled([
        resolver.resolve4(host),
        resolver.resolve6(host),
      ]);
      if (
        found.some(
          (r) => r.status === "rejected" && r.reason?.code === "ETIMEOUT",
        )
      )
        throw discoveryError("deadline_exceeded");
      answers = found.flatMap((r, i) =>
        r.status === "fulfilled"
          ? r.value.map((address) => ({ address, family: i === 0 ? 4 : 6 }))
          : [],
      );
    } finally {
      context.signal.removeEventListener("abort", cancel);
    }
  } else {
    try {
      answers = await lookup(host, { all: true });
    } catch {
      throw discoveryError("resolution_failed");
    }
  }
  remaining(context);
  ensure(
    answers.every((a) => isIP(a.address) === a.family),
    "resolution_failed",
  );
  // Match the reference resolver: IPv6 first, retaining order within each family,
  // then remove duplicates before applying the address bound.
  const addresses = [...new Set(answers.sort((a, b) => b.family - a.family).map((a) => a.address))];
  ensure(addresses.length >= 1 && addresses.length <= 64, "resolution_failed");
  return addresses;
}
function systemCertificates(): string[] | undefined {
  if (typeof tls.getCACertificates !== "function") return undefined;
  try {
    const certificates = tls.getCACertificates("system");
    return certificates.length > 0 ? certificates : undefined;
  } catch (error) {
    systemCertificateError(error);
  }
}
function tlsSocket(
  ip: string,
  url: URL,
  source: DiscoverySource,
  context: Context,
): Promise<TLSSocket> {
  remaining(context);
  const host = normalizedHost(url),
    roots = source.cacerts;
  const ca =
    roots === "os"
      ? systemCertificates()
      : roots.map(
          (der) =>
            "-----BEGIN CERTIFICATE-----\n" +
            encodeBase64(der) +
            "\n-----END CERTIFICATE-----",
        );
  if (!ca) throw custodyError("unsupported_format");
  return new Promise((done, fail) => {
    const socket = connect(
      Object.assign(Object.create(null), {
        host: ip,
        port: Number(url.port || 443),
        servername: isIP(host) ? "" : host,
        rejectUnauthorized: true,
        minVersion: "TLSv1.2",
        ALPNProtocols: ["http/1.1"],
        ca,
        checkServerIdentity: (
          _name: string,
          cert: Parameters<typeof checkServerIdentity>[1],
        ) => checkServerIdentity(host, cert),
        lookup: () => {
          throw discoveryError("address_denied");
        },
      }),
    );
    const abort = () => {
      socket.destroy();
      fail(discoveryError("deadline_exceeded"));
    };
    context.signal.addEventListener("abort", abort, { once: true });
    const cleanup = () => context.signal.removeEventListener("abort", abort);
    socket.once("error", (error) => {
      cleanup();
      fail(sslError(error));
    });
    socket.once("secureConnect", () => {
      try {
        remaining(context);
        checkPeer({address: socket.remoteAddress, port: socket.remotePort}, ip,
          Number(url.port || 443), source.permittedAddresses);
        cleanup();
        done(socket);
      } catch (error) {
        cleanup();
        socket.destroy();
        fail(error);
      }
    });
    if (context.signal.aborted) abort();
  });
}
async function connected(
  url: URL,
  source: DiscoverySource,
  context: Context,
  servers?: readonly string[],
): Promise<TLSSocket> {
  const addresses = await resolve(normalizedHost(url), context, servers);
  ensure(
    addresses.every((ip) =>
      unwrap(addressAllowed(ip, source.permittedAddresses), "address_denied"),
    ),
    "address_denied",
  );
  let last: unknown = discoveryError("connect_failed");
  for (const ip of addresses) {
    try {
      return await tlsSocket(ip, url, source, context);
    } catch (error) {
      allowConnectionRetry(error);
      // A connect-class failure preserves an earlier TLS failure across addresses.
      if (error && typeof error === 'object' && 'reason' in error && error.reason === 'tls_failed') last = error;
      remaining(context);
    }
  }
  throw last;
}
async function get(
  url: URL,
  source: DiscoverySource,
  context: Context,
  servers?: readonly string[],
): Promise<{
  status: number;
  fs: ReturnType<typeof fields>;
  encoded: Uint8Array;
}> {
  const socket = await connected(url, source, context, servers);
  // HTTPS receives only an already connected, peer-checked TLS socket. No proxy,
  // pooled connection or late DNS lookup participates in this private agent.
  const agent = new Agent({
    keepAlive: false,
    maxCachedSessions: 0,
    proxyEnv: Object.create(null),
  });
  agent.createConnection = () => socket;
  let response: IncomingMessage | undefined;
  try {
    remaining(context);
    return await new Promise((done, fail) => {
      const req = request(
        Object.assign(Object.create(null), {
          hostname: normalizedHost(url),
          port: Number(url.port || 443),
          method: "GET",
          path: url.pathname + url.search,
          agent,
          maxHeaderSize: 16384,
          insecureHTTPParser: false,
          joinDuplicateHeaders: false,
          headers: {
            Host: sourceAuthority(url),
            Accept:
              source.type === "directory"
                ? "application/http-message-signatures-directory+json"
                : "application/json, application/jwk-set+json",
            "Accept-Encoding": "gzip",
            Connection: "close",
          },
          lookup: () => {
            throw discoveryError("address_denied");
          },
        }),
      );
      req.maxHeadersCount = 0;
      const abort = () => {
        req.destroy();
        socket.destroy();
        response?.destroy();
        fail(discoveryError("deadline_exceeded"));
      };
      context.signal.addEventListener("abort", abort, { once: true });
      const cleanup = () => {
        context.signal.removeEventListener("abort", abort);
        socket.removeListener("data", onWire);
      };
      const reject = (error: unknown) => {
        cleanup();
        fail(error);
        req.destroy();
        response?.destroy();
        socket.destroy();
      };
      // Observe TLS plaintext before Node's HTTP parser strips chunk framing.
      let wireBytes = 0, head = "", line = "", mode: "head" | "line" | "data" | "ending" | "done" = "head", left = 0;
      const onWire = (chunk: Buffer) => {
        try {
          remaining(context);
          wireBytes += chunk.length;
          ensure(wireBytes <= source.maxBytes * 16 + 32768, "limit");
          for (let i = 0; i < chunk.length; i++) {
            if (mode === "done") break;
            if (mode === "data" || mode === "ending") {
              const take = Math.min(left, chunk.length - i);
              left -= take; i += take - 1;
              if (left === 0) {
                if (mode === "data") { mode = "ending"; left = 2; }
                else mode = "line";
              }
              continue;
            }
            if (mode === "head") {
              head += String.fromCharCode(chunk[i]!);
              ensure(head.length <= 16384, "limit");
              if (head.endsWith("\r\n\r\n")) {
                mode = /\r\ntransfer-encoding:[ \t]*chunked[ \t]*\r\n/i.test(head) ? "line" : "done";
                head = "";
              } else ensure(head.length < 16384, "limit");
            } else {
              line += String.fromCharCode(chunk[i]!);
              ensure(line.length <= 1024, "limit");
              if (line.endsWith("\r\n")) {
                const digits = line.slice(0, -2).split(";")[0]!;
                ensure(/^[0-9a-fA-F]{1,8}$/.test(digits), "invalid_response");
                left = Number.parseInt(digits, 16);
                line = ""; mode = left === 0 ? "done" : "data";
              }
            }
          }
        } catch (error) { reject(error); }
      };
      socket.prependListener("data", onWire);
      req.on("information", info => reject(discoveryError("unexpected_status", info.statusCode)));
      req.on("upgrade", (res, upgraded) => {
        reject(discoveryError("unexpected_status", res.statusCode));
        upgraded.destroy();
      });
      req.on("error", (error) => {
        cleanup();
        const code = (error as { code?: string }).code;
        fail(
          discoveryError(
            code === "HPE_HEADER_OVERFLOW" ? "limit" : "invalid_response",
          ),
        );
      });
      req.on("response", (res) => {
        response = res;
        res.on("error", () => {
          cleanup();
          fail(discoveryError(context.signal.aborted ? "deadline_exceeded" : "invalid_response"));
        });
        try {
          remaining(context);
          ensure(
            res.statusCode !== undefined &&
              res.statusCode >= 100 &&
              res.statusCode <= 599,
            "invalid_response",
          );
          const pairs: [string, string][] = [];
          for (let i = 0; i < res.rawHeaders.length; i += 2)
            pairs.push([res.rawHeaders[i]!, res.rawHeaders[i + 1]!]);
          const fs = fields(pairs),
            length = header(fs, "content-length"),
            transfer = header(fs, "transfer-encoding");
          ensure(length === null || transfer === null, "invalid_response");
          ensure(
            transfer === null || transfer.toLowerCase() === "chunked",
            "invalid_response",
          );
          ensure(
            length === null || /^[0-9]{1,10}$/.test(length),
            "invalid_response",
          );
          if (res.statusCode !== 200) {
            cleanup();
            res.destroy();
            done({ status: res.statusCode, fs, encoded: new Uint8Array() });
            return;
          }
          ensure(length === null || Number(length) <= source.maxBytes, "limit");
          const chunks: Uint8Array[] = [];
          let size = 0;
          res.on("data", (chunk: Buffer) => {
            try {
              remaining(context);
              size += chunk.length;
              ensure(size <= source.maxBytes, "limit");
              chunks.push(new Uint8Array(chunk));
            } catch (error) {
              cleanup();
              fail(error);
              res.destroy();
              socket.destroy();
            }
          });
          res.on("end", () => {
            try {
              remaining(context);
              ensure(
                res.complete && (length === null || Number(length) === size),
                "invalid_response",
              );
              const encoded = new Uint8Array(size);
              let offset = 0;
              for (const chunk of chunks) {
                encoded.set(chunk, offset);
                offset += chunk.length;
              }
              cleanup();
              done({ status: res.statusCode!, fs, encoded });
            } catch (error) {
              cleanup();
              fail(error);
            }
          });
        } catch (error) {
          cleanup();
          fail(error);
          res.destroy();
          socket.destroy();
        }
      });
      if (context.signal.aborted) abort();
      else req.end();
    });
  } finally {
    response?.destroy();
    socket.destroy();
    agent.destroy();
  }
}
function redirectUrl(current: URL, location: string): URL {
  ensure(
    location.length >= 1 &&
      location.length <= 2048 &&
      !location.includes("\\") &&
      !location.includes("#") &&
      !/[\x00-\x20\x7f-\uffff]/.test(location),
    "redirect_denied",
  );
  try {
    return sourceUrl(new URL(location, current).href);
  } catch {
    throw discoveryError("redirect_denied");
  }
}
async function resource(
  url: URL,
  source: DiscoverySource,
  context: Context,
  servers?: readonly string[],
  hops = 0,
): Promise<Resource> {
  const { status, fs, encoded } = await get(url, source, context, servers);
  if ([301, 302, 303, 307, 308].includes(status)) {
    ensure(source.maxRedirects > 0, "redirect_denied");
    ensure(hops < source.maxRedirects, "redirect_limit");
    const location = header(fs, "location");
    ensure(location !== null, "redirect_denied");
    const target = redirectUrl(url, location);
    ensure(
      source.redirectScope === "any_https" ||
        sourceOrigin(target) === sourceOrigin(sourceUrl(source.location)),
      "redirect_denied",
    );
    return resource(target, source, context, servers, hops + 1);
  }
  if (status !== 200) throw discoveryError("unexpected_status", status);
  mediaType(fs, source.type);
  const decoded = await decodeBody(
    encoded,
    header(fs, "content-encoding"),
    source.type === "cimd"
      ? Math.min(source.maxDecodedBytes, 5120)
      : source.maxDecodedBytes,
    context,
  );
  remaining(context);
  return { fields: fs, encoded, decoded, location: url.href };
}
export async function fetch(
  source: unknown,
  input: unknown = {},
): Promise<Result<KeySet>> {
  try {
    ensure(isDiscoverySource(source), "invalid_source");
    if (source.cacerts === "os" && !systemCertificates()) return err(custodyError("unsupported_format"));
    const a = options(input, ["timeoutMs", "clock", "context", "dnsServers"]);
    const timeout = Object.hasOwn(a, "timeoutMs")
      ? a.timeoutMs
      : source.timeoutMs;
    ensure(
      Number.isSafeInteger(timeout) &&
        (timeout as number) >= 1 &&
        (timeout as number) <= 300000,
      "invalid_options",
    );
    ensure(
      !Object.hasOwn(a, "context") || isContext(a.context),
      "invalid_options",
    );
    const clock = Object.hasOwn(a, "clock") ? a.clock : systemClock;
    clockValue(clock);
    let servers: readonly string[] | undefined;
    if (Object.hasOwn(a, "dnsServers")) {
      servers = Object.freeze(
        Array.from(list(a.dnsServers, 16, 1), (s) => {
          ensure(
            typeof s === "string" &&
              s.length <= 64 &&
              /^[0-9a-fA-F:.\[\]]+$/.test(s),
            "invalid_options",
          );
          if (!isIP(s)) {
            const endpoint = /^(\[[0-9a-fA-F:]+\]|[0-9.]+):([0-9]+)$/.exec(s);
            ensure(
              endpoint &&
                isIP(endpoint[1]!.replace(/^\[|\]$/g, "")) &&
                Number(endpoint[2]) >= 1 &&
                Number(endpoint[2]) <= 65535,
              "invalid_options",
            );
          }
          return s;
        }),
      );
    }
    // Literal denial is synchronous validation, before scheduling any timed work.
    // Otherwise contention can replace address_denied with a dispatch deadline.
    const literal = normalizedHost(sourceUrl(source.location));
    if (isIP(literal)) ensure(unwrap(addressAllowed(literal, source.permittedAddresses), "address_denied"), "address_denied");
    const context = unwrap(
      withDeadline({
        timeoutMs: Math.min(timeout as number, source.timeoutMs),
        ...(isContext(a.context) ? { parent: a.context } : {}),
      }),
      "invalid_options",
    );
    const result = await run(context, async () => {
      try {
        const outer = await resource(
          sourceUrl(source.location),
          source,
          context,
          servers,
        );
        const now = clockValue(clock);
        if (source.type === "cimd") {
          const doc = bodyDocument(outer.decoded, source);
          ensure(doc.client_id === source.location, "client_id_mismatch");
          ensure(
            !(Object.hasOwn(doc, "jwks") && Object.hasOwn(doc, "jwks_uri")),
            "ambiguous_key_source",
          );
          if (Object.hasOwn(doc, "jwks_uri")) {
            const url = sourceUrl(doc.jwks_uri);
            ensure(
              sourceOrigin(url) === sourceOrigin(sourceUrl(source.location)),
              "redirect_denied",
            );
            // The subresource has JWKS media/body ceilings, original CIMD provenance.
            const nestedSource = unwrap(
              DiscoverySource.create({
                ...source,
                type: "jwks_uri",
                location: url.href,
              }),
              "invalid_source",
            );
            const nested = await resource(url, nestedSource, context, servers);
            const result = await fromResource(
              source,
              nested.decoded,
              nested.encoded,
              now,
              nested.fields,
              nested.location,
              expiry(outer.fields, source, now),
              true,
              context,
            );
            remaining(context);
            return result;
          }
        }
        const result = await fromResource(
          source,
          outer.decoded,
          outer.encoded,
          now,
          outer.fields,
          outer.location,
          undefined,
          false,
          context,
        );
        remaining(context);
        return result;
      } catch (error) {
        return failure<KeySet>(error);
      }
    });
    return !result.ok && result.error.kind === "custody" && result.error.reason === "deadline_exceeded"
      ? err(
          discoveryError("deadline_exceeded"),
        )
      : result;
  } catch (error) {
    return failure(error, "invalid_options");
  }
}
export const Discovery = Object.freeze({ ...CoreDiscovery, fetch });
/** Node source creation fails closed when the OS trust store is unavailable or empty. */
export const DiscoverySource = Object.freeze({
  ...CoreSource,
  create(input: unknown): Result<import("./source.ts").DiscoverySource> {
    try {
      const result = CoreSource.create(input);
      if (result.ok && result.value.cacerts === "os" && !systemCertificates())
        return err(custodyError("unsupported_format"));
      return result;
    } catch (error) {
      return failure(error, "invalid_source");
    }
  },
});
