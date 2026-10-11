import test from "node:test";
import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkDocumentationLinks } from "./support/docs-links.ts";

test("all relative documentation links and anchors resolve", async t => {
  const result = await checkDocumentationLinks();
  assert.ok(result.links > 0, "known relative links must be measured");
  t.diagnostic(`${result.files} Markdown files; ${result.links} relative links`);
});

test("planted broken file and heading links fail in a temporary documentation copy", async () => {
  const directory = await mkdtemp(join(tmpdir(), "request-seal-links-"));
  try {
    for (const file of ["README.md", "CONTRIBUTING.md", "SECURITY.md", "docs"]) await cp(file, join(directory, file), {recursive: true});
    // Isolate the Markdown parser's behavior from unrelated copied links.
    await writeFile(join(directory, "README.md"), "# Known heading\n\n[positive](#known-heading)\n[positive reference][heading]\n\n[heading]: #known-heading\n");
    await writeFile(join(directory, "CONTRIBUTING.md"), "# Contributing\n");
    await writeFile(join(directory, "SECURITY.md"), "# Security\n");
    await rm(join(directory, "docs"), {recursive: true});
    await mkdir(join(directory, "docs"));
    assert.deepEqual(await checkDocumentationLinks(directory), {files: 3, links: 2});
    const readme = join(directory, "README.md");
    await writeFile(readme, "# Known heading\n\n[positive](#known-heading)\n[broken](missing-document.md)\n");
    await assert.rejects(checkDocumentationLinks(directory), /README\.md: missing-document\.md:/);
    await writeFile(readme, "# Known heading\n\n[broken][anchor]\n\n[anchor]: #missing-heading\n");
    await assert.rejects(checkDocumentationLinks(directory), /README\.md: #missing-heading: heading or anchor/);
    await writeFile(readme, "# Known heading\n\n[positive](CONTRIBUTING.md)\n");
    assert.deepEqual(await checkDocumentationLinks(directory), {files: 3, links: 1});
    await writeFile(readme, "# Known heading\n\n[wrong case](contributing.md)\n");
    await assert.rejects(checkDocumentationLinks(directory), /README\.md: contributing\.md: path component/);
  } finally { await rm(directory, {recursive: true, force: true}); }
});
