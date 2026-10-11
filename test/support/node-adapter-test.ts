import nodeTest from "node:test";
import assert from "node:assert/strict";
import {execFileWithEnvSync as execFileSync} from "./child-env.ts";
import { fileURLToPath } from "node:url";

/** Native lanes exercise Node HTTP adapters on their actual Node substrate. */
export function nodeAdapterTest(file: string): typeof nodeTest {
  if (!process.versions.deno && !process.versions.bun) return nodeTest;
  return ((name: string, options: unknown, fn?: unknown) => {
    const attrs = typeof options === "function" ? {} : options as object;
    const requestedTimeout = (attrs as {timeout?: unknown}).timeout;
    const timeout = typeof requestedTimeout === "number" ? Math.max(30000, requestedTimeout) : 30000;
    return nodeTest(name, attrs, t => {
      const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const env = { ...process.env };
      delete env.NODE_TEST_CONTEXT;
      const output = execFileSync("node", [
        "--unhandled-rejections=strict", "--experimental-strip-types", "--no-warnings",
        "--test", "--test-reporter=tap", `--test-name-pattern=^${escaped}$`,
        fileURLToPath(file),
      ], { encoding: "utf8", timeout, env });
      assert.match(output, /^# pass 1$/m);
      assert.match(output, /^# fail 0$/m);
      t.diagnostic(`Node adapter subprocess:\n${output}`);
    });
  }) as typeof nodeTest;
}
