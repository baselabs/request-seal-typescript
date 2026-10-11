import test from "node:test";
import assert from "node:assert/strict";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { documentationFences, executeFence, extractFences, runtime } from "./support/docs-fences.ts";

const fences = documentationFences();
const selected = fences.filter(fence => fence.runtime === runtime);
test("README verification excerpts match their complete programs and stay within fifteen lines", async () => {
  const readme = await readFile("README.md", "utf8");
  const snippets = [...readme.matchAll(/<!-- verification-excerpt: (express|hono) -->\n```typescript\n([\s\S]*?)\n```/g)];
  assert.deepEqual(snippets.map(match => match[1]), ["express", "hono"]);
  for (const snippet of snippets) {
    const expectedRuntime = snippet[1] === "hono" ? "deno" : "node";
    const program = fences.find(fence => fence.file === "README.md" && fence.runtime === expectedRuntime && fence.source.includes("// ---- Your server:"));
    assert.ok(program);
    const excerpt = /\/\/ ---- Your server:[^\n]*\n([\s\S]*?)\n\/\/ ---- End of the verification code ----/.exec(program.source)?.[1];
    assert.ok(excerpt);
    assert.ok(excerpt.split("\n").length <= 15);
    assert.equal(snippet[2], excerpt, `${snippet[1]} excerpt must be the code executed by its complete fence`);
  }
});
test("documentation fences are assigned to their declared runtime", t => {
  assert.ok(fences.some(fence => fence.file === "README.md"), "README must contain TypeScript programs");
  t.diagnostic(`${runtime}: ${selected.length} TypeScript fences`);
});
// Register programs separately so the native runner's per-test timeout never
// limits the cumulative execution time of an expanding guide collection.
for (const fence of selected)
  test(`${fence.file}: fence ${fence.index} (${runtime})`, async () => { await executeFence(fence); });

test("fence extraction honors runtime annotations and ignores shell blocks", () => {
  const source = "```sh\n```ts\nthrow Error('shell');\n```\n<!-- run: deno -->\n```ts\nconsole.log('deno');\n```\n<!-- run: bun -->\n```ts\nconsole.log('bun');\n```\n```ts\nconsole.log('node');\n```";
  assert.deepEqual(extractFences("example.md", source).map(fence => fence.runtime), ["deno", "bun", "node"]);
});

test("a planted failing fence in a temporary documentation copy is rejected", async () => {
  const copy = await mkdtemp(join(tmpdir(), "request-seal-doc-copy-"));
  try {
    await cp("README.md", join(copy, "README.md"));
    const annotation = runtime === "node" ? "" : `<!-- run: ${runtime} -->\n`;
    await writeFile(join(copy, "README.md"), `${await readFile(join(copy, "README.md"), "utf8")}\n${annotation}\`\`\`ts\nconsole.error('planted fence failure');\nthrow new Error('planted fence failure');\n\`\`\`\n`);
    const plant = (await documentationFences(copy)).at(-1)!;
    await assert.rejects(executeFence(plant), /README\.md: fence \d+ .*exit [1-9][\s\S]*planted fence failure/);
  } finally { await rm(copy, {recursive: true, force: true}); }
});

test("a nonterminating fence is killed and identified", {timeout: 15_000}, async () => {
  await assert.rejects(executeFence({file: "timeout.md", index: 1, runtime, source: "console.error('waiting fence'); setInterval(() => {}, 1000);"}), /timeout\.md: fence 1 .*timeout after ten seconds[\s\S]*waiting fence/);
});

test("complete programs resolve the package root and every code subpath by name", async () => {
  const pkg = JSON.parse(await readFile("package.json", "utf8"));
  const names = Object.keys(pkg.exports).filter(name => name !== "./package.json").map(name => name === "." ? pkg.name : pkg.name + name.slice(1));
  const imports = names.map((name, index) => `import * as entry${index} from ${JSON.stringify(name)}; if (Object.keys(entry${index}).length === 0) throw Error('empty entry');`).join("\n");
  await executeFence({file: "package exports", index: 1, runtime, source: `${imports}\nimport {DigestState} from '@request-seal/core';\nimport {createNodeHasher} from '@request-seal/core/node-hasher';\nconst hasher = createNodeHasher(); if (!hasher.ok) throw Error(hasher.error.reason);\nconst state = await DigestState.create('content', ['sha-256'], hasher.value); if (!state.ok) throw Error(state.error.reason);\nconst updated = await state.value.update(new TextEncoder().encode('abc')); if (!updated.ok) throw Error(updated.error.reason);\nconst digest = await state.value.finish(); if (!digest.ok) throw Error(digest.error.reason);`});
});
