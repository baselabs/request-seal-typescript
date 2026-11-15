import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// The board has exactly one four-column board and at most one two-column legend.
// Every table line has its header's width; every roadmap row occurs once,
// with one of six Status badges and exactly one matching counts line.
// ROADMAP_PATH names another file, so the check can run against a scratch copy.

const ROADMAP =
  process.env.ROADMAP_PATH ??
  fileURLToPath(new URL("../docs/ROADMAP.md", import.meta.url));
const BADGES = ["✅", "🟢", "🟡", "🔵", "⚪", "⛔"] as const;
const START = "<!-- status-board:start -->";
const FINISH = "<!-- status-board:end -->";
const LEGEND_HEADER = ["Badge", "Meaning"];
const BOARD_HEADER = ["Status", "Row", "Where it stands", "Watch"];
const ROW_HEADERS = [
  "| ID | Outcome | Acceptance | Waits on |",
  "| ID | Outcome | Acceptance | Evidence |",
];

const separator = (cell: string): boolean => /^:?-+:?$/.test(cell);

const cells = (line: string): string[] =>
  line
    .trim()
    .replace(/^\|+/, "")
    .replace(/\|+$/, "")
    .split("|")
    .map((cell) => cell.trim());

function boardTables(board: string): string[][][] {
  const groups: string[][] = [];
  let current: string[] | undefined;
  for (const line of board.split("\n")) {
    if (line.startsWith("|")) {
      if (current === undefined) {
        current = [];
        groups.push(current);
      }
      current.push(line);
    } else current = undefined;
  }
  return groups.map((lines) =>
    lines.map(cells).filter((row) => !row.every(separator)),
  );
}

function sameHeader(header: readonly string[] | undefined, expected: readonly string[]): boolean {
  return header !== undefined && header.length === expected.length &&
    header.every((cell, index) => cell === expected[index]);
}

function rowIds(tables: string): string[] {
  const ids: string[] = [];
  let inTable = false;
  for (const line of tables.split("\n")) {
    if (ROW_HEADERS.includes(line)) inTable = true;
    else if (inTable && line.startsWith("|")) ids.push(cells(line)[0] ?? "");
    else inTable = false;
  }
  return ids.filter((id) => !separator(id));
}

function duplicates(values: readonly string[]): string[] {
  return values.filter((value, index) => values.indexOf(value) !== index);
}

function load(): { board: string; boardTables: string[][][]; entries: string[][]; ids: string[] } {
  const text = readFileSync(ROADMAP, "utf8");
  const afterStart = text.split(START);
  assert.equal(afterStart.length, 2, "exactly one board start marker");
  const parts = (afterStart[1] ?? "").split(FINISH);
  assert.equal(parts.length, 2, "exactly one board end marker");
  const board = parts[0] ?? "";
  const tables = parts[1] ?? "";
  assert.ok(!tables.includes(START), "exactly one board");
  const tablesOnBoard = boardTables(board);
  const entries = tablesOnBoard
    .filter(([header]) => sameHeader(header, BOARD_HEADER))
    .flatMap((table) => table.slice(1));
  return { board, boardTables: tablesOnBoard, entries, ids: rowIds(tables) };
}

test("the board holds one four-column board and at most one legend, each line at its width", () => {
  const { boardTables } = load();
  const headers = boardTables.map(([header]) => header ?? []);
  const unknown = headers.filter((header) =>
    !sameHeader(header, LEGEND_HEADER) && !sameHeader(header, BOARD_HEADER),
  );
  assert.deepEqual(unknown, [], `a table other than the legend or the board: ${JSON.stringify(unknown)}`);
  assert.equal(headers.filter((header) => sameHeader(header, BOARD_HEADER)).length, 1, "exactly one board table");
  assert.ok(headers.filter((header) => sameHeader(header, LEGEND_HEADER)).length <= 1, "at most one legend table");
  const misshapen = boardTables.flatMap(([header = [], ...rows]) =>
    rows.filter((row) => row.length !== header.length),
  );
  assert.deepEqual(misshapen, [], `a line whose width differs from its table: ${JSON.stringify(misshapen)}`);
});

test("every row appears on the board exactly once", () => {
  const { entries, ids } = load();
  assert.notDeepEqual(ids, [], "the roadmap has no rows");
  assert.deepEqual(duplicates(ids), [], "row IDs must be unique");
  const names = entries.map((row) => row[1] ?? "");
  assert.deepEqual(duplicates(names), [], "a board line repeats");
  assert.deepEqual(
    [...names].sort(),
    [...ids].sort(),
    `board and rows differ: missing ${JSON.stringify(ids.filter((id) => !names.includes(id)))}, unknown ${JSON.stringify(names.filter((name) => !ids.includes(name)))}`,
  );
});

test("every Status is one of the six badges", () => {
  const { entries } = load();
  const badges: readonly string[] = BADGES;
  const bad = entries.filter((row) => !badges.includes(row[0] ?? ""));
  assert.deepEqual(
    bad.map((row) => row.slice(0, 2)),
    [],
    "Status outside the six badges",
  );
});

test("one counts line matches the board as a whole line", () => {
  const { board, entries, ids } = load();
  const statuses = entries.map((row) => row[0]);
  const counts = BADGES.map(
    (badge) => [badge, statuses.filter((status) => status === badge).length] as const,
  );
  assert.equal(
    counts.reduce((sum, [, n]) => sum + n, 0),
    ids.length,
  );
  const expected = `Counts: ${counts.map(([badge, n]) => `${badge} ${n}`).join(" · ")}`;
  const lines = board.split("\n").filter((line) => line.startsWith("Counts:"));
  assert.deepEqual(lines, [expected], `expected exactly ${JSON.stringify(expected)}`);
});
