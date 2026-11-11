import { execFileSync } from "node:child_process";

/** Git-visible files in the current working tree, including unstaged changes. */
export function workingTreeFiles(root: string, patterns: readonly string[]): string[] {
  const files = (options: readonly string[]) => execFileSync("git",
    ["ls-files", "-z", ...options, "--", ...patterns],
    { cwd: root, encoding: "utf8" }).split("\0").filter(Boolean);
  const deleted = new Set(files(["--deleted"]));
  return [...new Set(files(["--cached", "--others", "--exclude-standard", "--exclude=.[!.]*/"]))]
    .filter(file => !deleted.has(file));
}
