import { spawn } from "node:child_process";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { readFileSync, readdirSync } from "node:fs";

export type Runtime = "node" | "deno" | "bun";
export type Fence = Readonly<{ file: string; index: number; runtime: Runtime; source: string }>;
export const runtime: Runtime = process.versions.deno ? "deno" : process.versions.bun ? "bun" : "node";

/** Extract complete TypeScript programs, ignoring fences inside other code blocks. */
export function extractFences(file: string, markdown: string): Fence[] {
  const lines = markdown.split(/\r?\n/), fences: Fence[] = [];
  for (let line = 0; line < lines.length; line++) {
    const opening = /^ {0,3}(`{3,}|~{3,})(.*)$/.exec(lines[line]!);
    if (!opening) continue;
    const marker = opening[1]!, language = opening[2]!.trim();
    const annotation = /^<!-- run: (deno|bun) -->$/.exec(lines[line - 1] ?? "");
    const selected: Runtime = annotation?.[1] === "deno" ? "deno" : annotation?.[1] === "bun" ? "bun" : "node";
    const start = ++line;
    while (line < lines.length && !new RegExp(`^ {0,3}${marker[0]}{${marker.length},}\\s*$`).test(lines[line]!)) line++;
    if (language !== "ts") continue;
    if (line === lines.length) throw new Error(`${file}: unclosed TypeScript fence`);
    fences.push({ file, index: fences.length + 1, runtime: selected, source: lines.slice(start, line).join("\n") });
  }
  return fences;
}

/** Read README and every immediate Markdown guide in deterministic order. */
export function documentationFences(root = process.cwd()): Fence[] {
  let guides: string[] = [];
  try { guides = readdirSync(join(root, "docs/guides")).filter(name => name.endsWith(".md")).sort(); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  const files = ["README.md", ...guides.map(name => `docs/guides/${name}`)];
  const fences: Fence[] = [];
  for (const file of files) fences.push(...extractFences(file, readFileSync(join(root, file), "utf8")));
  return fences;
}

/** Execute unchanged source using package-name resolution and a hard ten-second deadline. */
export async function executeFence(fence: Fence, trailingSource = ""): Promise<string> {
  const directory = await mkdtemp(resolve("test/.tmp-doc-fence-"));
  const label = `${fence.file}: fence ${fence.index} (${fence.runtime})`;
  try {
    await writeFile(join(directory, "package.json"), JSON.stringify({type: "module", dependencies: {"@request-seal/core": "*"}}));
    await mkdir(join(directory, "node_modules/@request-seal"), {recursive: true});
    await symlink(process.cwd(), join(directory, "node_modules/@request-seal/core"), "dir");
    const program = join(directory, "example.ts");
    await writeFile(program, fence.source + trailingSource);
    const command = fence.runtime === runtime ? process.execPath : fence.runtime;
    const args = fence.runtime === "node" ? ["--unhandled-rejections=strict", "--experimental-strip-types", "--no-warnings", program]
      : fence.runtime === "deno" ? ["run", "--no-check", "--allow-all", "--node-modules-dir=manual", program] : ["run", program];
    const env = {...process.env};
    delete env.NODE_TEST_CONTEXT;
    return await new Promise<string>((accept, reject) => {
      const child = spawn(command, args, {cwd: directory, env, stdio: ["ignore", "pipe", "pipe"], detached: true});
      let output = "", timedOut = false;
      const terminate = () => {
        try { if (child.pid) process.kill(-child.pid, "SIGKILL"); }
        catch { child.kill("SIGKILL"); }
      };
      const timer = setTimeout(() => {
        timedOut = true; terminate();
        reject(new Error(`${label}: timeout after ten seconds\n${output}`));
      }, 10_000);
      const capture = (chunk: Buffer) => {
        output += chunk.toString();
        if (output.length > 1024 * 1024) output = "[earlier output omitted]\n" + output.slice(-1024 * 1024);
      };
      child.stdout.on("data", capture); child.stderr.on("data", capture);
      child.once("error", error => { clearTimeout(timer); reject(new Error(`${label}: ${error.message}\n${output}`)); });
      child.once("close", (code, signal) => {
        clearTimeout(timer);
        if (timedOut || code !== 0) reject(new Error(`${label}: ${timedOut ? "timeout after ten seconds" : `exit ${code}, signal ${signal}`}\n${output}`));
        else accept(output);
      });
    });
  } finally { await rm(directory, {recursive: true, force: true}); }
}
