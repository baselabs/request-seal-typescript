import test from "node:test";
import assert from "node:assert/strict";
import { cp, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { execFileSync } from "node:child_process";
import { documentationFences, executeFence, extractFences, runtime } from "./support/docs-fences.ts";

const fences = documentationFences();
const selected = fences.filter(fence => fence.runtime === runtime);
test("README verification excerpts match their complete programs and stay within fifteen lines", async () => {
  const readme = await readFile("README.md", "utf8");
  const snippets = [...readme.matchAll(/<!-- verification-excerpt: (express|hono) -->\n(?:<!-- run: deno -->\n)?```typescript\n([\s\S]*?)\n```/g)];
  assert.deepEqual(snippets.map(match => match[1]), ["express", "hono"]);
  for (const snippet of snippets) {
    const expectedRuntime = snippet[1] === "hono" ? "deno" : "node";
    const program = fences.find(fence => fence.file === "README.md" && fence.runtime === expectedRuntime && !fence.excerpt && fence.source.includes("// ---- Your server:"));
    assert.ok(program);
    const excerpt = /\/\/ ---- Your server:[^\n]*\n([\s\S]*?)\n\/\/ ---- End of the verification code ----/.exec(program.source)?.[1];
    assert.ok(excerpt);
    assert.ok(excerpt.split("\n").length <= 15);
    assert.equal(snippet[2], excerpt, `${snippet[1]} excerpt must be the code executed by its complete fence`);
  }
});
test("documentation fences are assigned to their declared runtime", t => {
  assert.ok(fences.some(fence => fence.file === "README.md"), "README must contain TypeScript programs");
  for (const declared of ["node", "deno", "bun"]) assert.ok(fences.some(f => f.runtime === declared), `${declared} must execute examples`);
  t.diagnostic(`${runtime}: ${selected.length} TypeScript fences`);
});
// Register programs separately so the native runner's per-test timeout never
// limits the cumulative execution time of an expanding guide collection.
for (const fence of selected)
  test(`${fence.file}: fence ${fence.index} (${runtime})`, async () => { await executeFence(fence); });

test("fence extraction accepts both TypeScript spellings and CommonMark containers", () => {
  const source = "~~~typescript\nconsole.log('tilde');\n~~~\n> <!-- run: deno -->\n> ```ts\n> console.log('quote');\n> ```\n- item\n\n  ```ts\n  console.log('list');\n  ```";
  assert.deepEqual(extractFences("example.md", source).map(f => f.runtime), ["node", "deno", "node"]);
  assert.equal(extractFences("example.md", "```sh\necho hello\n```\n").length, 0);
});

for (const marker of ["<!-- Run: deno -->", "<!-- run: Deno -->", "<!-- run : bun -->", "<!-- runtime: deno -->", "<!-- run: node -->", "<!-- run:deno -->", "<!--\nrun: deno -->", "<!-- run: deno > -->"])
  for (const gap of ["\n", "\n\n"])
    test(`invalid runtime annotation rejects: ${marker}, gap ${gap.length}`, () => {
      assert.throws(() => extractFences("example.md", marker + gap + "```ts\nconsole.log('bad');\n```"), /runtime annotation/);
    });
for (const info of ["TS", "TypeScript", "tsx", "ts extra", "typescript title=example", "mts", "cts", "application/typescript", "language-ts"])
  test(`invalid TypeScript info string rejects: ${info}`, () => {
    assert.throws(() => extractFences("example.md", "```" + info + "\nconsole.log('bad');\n```"), /TypeScript info/);
  });
for (const wrapper of ["````", "~~~"])
  test(`nested TypeScript fence is rejected inside ${wrapper}`, () => {
    assert.throws(() => extractFences("example.md", wrapper + "text\n```ts\nthrow Error('nested');\n```\n" + wrapper), /nested TypeScript fence/);
  });
for (const opener of ["```ts", "~~~typescript", "```sh"])
  test(`HTML blocks cannot conceal a fence opener: ${opener}`, () => {
    assert.throws(() => extractFences("example.md", `<details>\n${opener}\nthrow Error('hidden');\n${opener.slice(0, 3)}\n</details>`), /HTML block contains a fence opener/);
  });
test("unclosed TypeScript fences reject", () => {
  assert.throws(() => extractFences("example.md", "~~~ts\nthrow Error('unclosed');"), /unclosed TypeScript fence/);
});
test("fence collection includes Markdown outside the guides", async () => {
  const copy = await mkdtemp(join(tmpdir(), "request-seal-doc-coverage-"));
  try {
    await writeFile(join(copy, "README.md"), "# Example\n");
    await mkdir(join(copy, "other/nested"), {recursive: true});
    await writeFile(join(copy, "other/nested/example.md"), "```typescript\nthrow Error('outside guides');\n```\n");
    await writeFile(join(copy, "CHANGELOG.md"), "```ts\nthrow Error('record');\n```\n");
    const found = documentationFences(copy);
    assert.equal(found.length, 1);
    assert.equal(found[0]?.file, "other/nested/example.md");
    await assert.rejects(executeFence(found[0]!), /outside guides/);
  } finally { await rm(copy, {recursive: true, force: true}); }
});

test("new repository Markdown cannot bypass fence collection before staging", async () => {
  const copy = await mkdtemp(join(tmpdir(), "request-seal-coverage-"));
  try {
    // Git reads the real index here; object history is unnecessary for ls-files.
    await mkdir(join(copy, ".git/objects"), {recursive: true});
    await mkdir(join(copy, ".git/refs"), {recursive: true});
    for (const file of ["HEAD", "index", "config"]) await cp(join(".git", file), join(copy, ".git", file));
    // Preserve the Git-backed collector while isolating the probe from the working tree.
    const files = execFileSync("git", ["ls-files", "--", "*.md"], {encoding: "utf8"}).trim().split("\n");
    for (const file of files) {
      await mkdir(dirname(join(copy, file)), {recursive: true});
      await cp(file, join(copy, file));
    }
    const file = "test/docs-coverage.md";
    await mkdir(join(copy, "test"), {recursive: true});
    await writeFile(join(copy, file), "```typescript\nthrow Error('new repository fence');\n```\n");
    const collected = documentationFences(copy);
    assert.ok(collected.some(f => f.file === "README.md"), "known README programs remain visible through the copied index");
    const found = collected.find(f => f.file === file);
    assert.ok(found);
    await assert.rejects(executeFence(found), /new repository fence/);
  } finally { await rm(copy, {recursive: true, force: true}); }
});

test("runtime-looking comments reject even on shell fences", () => {
  assert.throws(() => extractFences("example.md", "<!-- Run: deno -->\n```sh\necho hi\n```"), /runtime annotation/);
});

test("longer closing markers and four-backtick TypeScript fences execute", async () => {
  for (const [open, close] of [["````typescript", "`````"], ["~~~ts", "~~~~"]]) {
    const [fence] = extractFences("example.md", `${open}\nthrow Error('CommonMark program');\n${close}\n`);
    assert.ok(fence);
    await assert.rejects(executeFence(fence), /CommonMark program/);
  }
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
