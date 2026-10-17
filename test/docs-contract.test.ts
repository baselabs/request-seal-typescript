import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

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
  for (const document of documents.filter((path) => path === "README.md" || path.startsWith("docs/guides/") || path === "docs/design/threat-model.md")) {
    for (const match of read(document).matchAll(/`([^`\s]+)`/g)) {
      const token = match[1]!.replace(/[.,;:]+$/, "");
      if (!roots.test(token) || /[*<>{}]/.test(token)) continue;
      assert.ok(existsSync(token.replace(/\/$/, "")), `${document}: ${token} does not exist`);
    }
  }
});

test("the README status table maps every reason and agrees with the signing guide", async () => {
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
  const patterns: {pattern: string; status: number}[] = [];
  for (const [status, cell] of statuses)
    for (const match of cell.matchAll(/`([^`]+)`/g)) patterns.push({pattern: match[1]!, status});
  for (const entry of ERROR_PARITY) {
    const matches = patterns.filter(({pattern}) => pattern.endsWith("*") ? entry.rule_id.startsWith(pattern.slice(0, -1)) : entry.rule_id === pattern);
    assert.ok(matches.length, `${entry.rule_id} is missing from the README`);
    const exact = matches.filter(({pattern}) => !pattern.endsWith("*"));
    const chosen = exact.length ? exact : matches;
    assert.equal(chosen.length, 1, `${entry.rule_id} has ambiguous README rows`);
    assert.equal(mapping[entry.rule_id], chosen[0]!.status, entry.rule_id);
  }
  for (const {pattern} of patterns)
    assert.ok(ERROR_PARITY.some(e => pattern.endsWith("*") ? e.rule_id.startsWith(pattern.slice(0, -1)) : e.rule_id === pattern), `unknown pattern: ${pattern}`);
});

test("the error reasons page explains every reason in the vocabulary exactly once, under its kind", () => {
  const known = ERROR_PARITY.map(entry => entry.rule_id);
  const listed: string[] = [];
  let section: string | null = null;
  for (const [index, line] of read("docs/reference/errors.md").split("\n").entries()) {
    const heading = /^## (.+)$/.exec(line);
    if (heading) { section = heading[1]!; continue; }
    if (!line.startsWith("| `")) continue;
    // Every reason row must parse; a malformed row fails instead of being skipped.
    const row = /^\| `([a-z0-9_]+)\/([a-z0-9_.]+)` \| ([^|]+) \| ([^|]+) \|$/.exec(line);
    assert.ok(row, `errors.md line ${index + 1} is not a well-formed reason row: ${line}`);
    assert.equal(row[1], section, `errors.md line ${index + 1}: ${row[1]}/${row[2]} sits under "## ${section}"`);
    assert.ok(row[3]!.trim() && row[4]!.trim(), `${row[1]}/${row[2]} has a meaning and an action`);
    listed.push(`${row[1]}/${row[2]}`);
  }
  assert.equal(new Set(listed).size, listed.length, "no reason is listed twice");
  assert.deepEqual([...listed].sort(), [...known].sort(), "every vocabulary reason, and only those, is listed");
});
