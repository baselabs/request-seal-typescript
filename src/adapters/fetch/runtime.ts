import { RUNTIME_MANAGED_FIELDS } from "../support.ts";
// Evidence: test/fixtures/adapters-fetch-wire.json and adapters-fetch-wire.test.ts.
export const FETCH_VERIFICATION_RUNTIMES = Object.freeze([
  "deno:2.5.6",
] as const);
const host = globalThis as typeof globalThis & {
  Deno?: { version?: { deno?: string } };
  Bun?: { version?: string };
  process?: { versions?: { node?: string } };
};
// Deno exposes Node compatibility globals on some entry points. Its own user
// agent is also evidence; a planted Deno marker on Node is insufficient.
const nativeDeno = host.Deno?.version?.deno && !host.Bun &&
  (!host.process?.versions?.node ||
    globalThis.navigator?.userAgent.startsWith("Deno/"));
const deno = nativeDeno ? host.Deno?.version?.deno : undefined;
export const runtime = deno
  ? `deno:${deno}`
  : host.Bun?.version
    ? `bun:${host.Bun.version}`
    : `node:${host.process?.versions?.node ?? "unknown"}`;
export const canVerify = (
  FETCH_VERIFICATION_RUNTIMES as readonly string[]
).includes(runtime);

// Runtime-owned signing fields, measured by the wire lane beside the allowlist.
export const FETCH_SIGNING_REFUSALS = Object.freeze({
  common: RUNTIME_MANAGED_FIELDS,
  node: Object.freeze(["sec-fetch-mode"]),
  deno: Object.freeze([] as string[]),
  bun: Object.freeze([] as string[]),
});
export const signingRefusals: readonly string[] = Object.freeze([
  ...FETCH_SIGNING_REFUSALS.common,
  ...FETCH_SIGNING_REFUSALS[
    runtime.startsWith("deno:")
      ? "deno"
      : runtime.startsWith("bun:")
      ? "bun"
      : "node"
  ],
]);
