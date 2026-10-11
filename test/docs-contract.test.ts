import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";

import { ERROR_PARITY } from "../src/index.ts";
import { documentationFiles } from "./support/docs-links.ts";
import { documentationFences, executeFence } from "./support/docs-fences.ts";

// Metadata, referenced paths, ADR shape, and the status table supplement the link check.
const documents = await documentationFiles();
const read = (path: string) => readFileSync(path, "utf8");

test("every document starts with the metadata line", () => {
  const pattern = /^\*\*Status:\*\* [^·]+ · \*\*Kind:\*\* [^·]+ · \*\*Updated:\*\* (?:January|February|March|April|May|June|July|August|September|October|November|December) \d{1,2}, \d{4} · \*\*Governed by:\*\* [^·]+ · \*\*Review when:\*\* .+$/;
  for (const document of documents) {
    const first = read(document).split(/\n\s*\n/, 1)[0]!.replace(/\s*\n\s*/g, " ");
    assert.match(first, pattern, `${document} must start with the Status, Kind, Updated, Governed by, and Review when line`);
  }
});

test("repository paths named in code spans exist", () => {
  const roots = /^(?:src|test|tools|scripts|docs|interop|conformance|bench|\.github)\//;
  for (const document of documents.filter((path) => path === "README.md" || path.startsWith("docs/guides/") || path.startsWith("docs/adr/") || path === "docs/design/threat-model.md")) {
    for (const match of read(document).matchAll(/`([^`\s]+)`/g)) {
      const token = match[1]!.replace(/[.,;:]+$/, "");
      if (!roots.test(token) || /[*<>{}]/.test(token)) continue;
      assert.ok(existsSync(token.replace(/\/$/, "")), `${document}: ${token} does not exist`);
    }
  }
});

test("decision records keep the reference format and are indexed", () => {
  const index = read("docs/adr/README.md");
  const records = readdirSync("docs/adr").filter((name) => /^\d{4}-.+\.md$/.test(name)).sort();
  assert.ok(records.length >= 7);
  records.forEach((name, i) => assert.equal(name.slice(0, 4), String(i + 1).padStart(4, "0"), "record numbers are consecutive"));
  for (const name of records) {
    const text = read(`docs/adr/${name}`);
    assert.ok(index.includes(`(${name})`), `${name} is listed in the index`);
    assert.match(text, /^# ADR \d{4}: .+$/m);
    for (const heading of ["Context", "Decision", "Strongest alternatives", "Deciding evidence and deletion test", "Consequences", "Acceptance"]) {
      assert.match(text, new RegExp(`^## ${heading}$`, "m"), `${name} needs a ${heading} section`);
    }
    assert.match(text, /`test\/[^`]+`/, `${name} cites the tests that enforce it`);
    assert.match(text, /`(?:src|tools|scripts)\/[^`]+`|`package\.json`/, `${name} cites the code that enforces it`);
  }
});

test("the README status table maps every core reason and agrees with the signing guide", async () => {
  const readme = read("README.md");
  const section = /^## Reason to HTTP status \(recommendation\)\n([\s\S]*?)^## /m.exec(readme)![1]!;
  assert.match(section, /recommendation/);
  const statuses = new Map<number, string>();
  for (const line of section.split("\n")) {
    const match = /^\| (\d{3}) \| (.+) \|$/.exec(line);
    if (match) statuses.set(Number(match[1]), match[2]!);
  }
  assert.deepEqual([...statuses.keys()], [400, 401, 403, 500, 503]);
  // The guide holds the mapping as a program. Run its exact source and print the mapping it computes.
  const fence = documentationFences().find((entry) => entry.file === "docs/guides/signing-and-verifying.md" && entry.source.includes("function statusFor"));
  assert.ok(fence, "the signing guide holds the status mapping program");
  const output = await executeFence(fence, "\nconsole.log(JSON.stringify(Object.fromEntries(ERROR_PARITY.map((e) => [e.rule_id, statusFor(e)]))));\n");
  const mapping = JSON.parse(output.trim().split("\n").pop()!) as Record<string, number>;
  const covered = new Set<string>();
  for (const [status, cell] of statuses) {
    for (const match of cell.matchAll(/`([a-z_]+\.[a-z_]+)`( \(unless noted below\)| with detail)?/g)) {
      const id = `core/${match[1]}`;
      if (match[2]) continue; // Detail-dependent: key.agent_unresolved resolves per detail.
      assert.ok(id in mapping, `${id} is a real core reason`);
      assert.equal(mapping[id], status, `${id} is mapped to ${mapping[id]} by the guide but ${status} by the README`);
      covered.add(id);
    }
  }
  for (const entry of ERROR_PARITY) {
    if (entry.kind === "core" && entry.reason !== "agent_unresolved") assert.ok(covered.has(entry.rule_id), `${entry.rule_id} is missing from the README table`);
  }
  for (const kind of ["message", "structured_fields", "signature_base", "digest", "custody", "discovery", "jose", "replay", "adapter"]) {
    assert.ok(new RegExp(kind.replace("_", "[_ ]"), "i").test(section), `${kind} errors are covered by the README table`);
  }
  assert.ok(/agent_unresolved/.test(section));
});
