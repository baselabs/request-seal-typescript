import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("the API reference includes every code export and fails on missing documentation", async () => {
  const pkg = JSON.parse(await readFile("package.json", "utf8"));
  const config = JSON.parse(await readFile("typedoc.json", "utf8"));
  const entries = Object.entries(pkg.exports).filter(([name]) => name !== "./package.json").map(([, target]) => {
    const typed = (target as {types: string}).types;
    return typed.replace(/^\.\/dist\//, "src/").replace(/\.d\.ts$/, ".ts");
  });
  assert.deepEqual([...config.entryPoints].sort(), entries.sort());
  assert.equal(config.treatWarningsAsErrors, true);
  assert.equal(config.validation.notDocumented, true);
  assert.equal(config.validation.notExported, true);
  assert.equal(config.validation.invalidLink, true);
});
