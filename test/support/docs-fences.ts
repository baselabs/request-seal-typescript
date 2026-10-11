import { execFileSync, spawn } from "node:child_process";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { existsSync, readFileSync, readdirSync } from "node:fs";

import MarkdownIt from "markdown-it";

export type Runtime = "node" | "deno" | "bun";
export type Fence = Readonly<{ file: string; index: number; runtime: Runtime; source: string; excerpt?: "express" | "hono"; completeSource?: string }>;
export const runtime: Runtime = process.versions.deno ? "deno" : process.versions.bun ? "bun" : "node";

const markdown = new MarkdownIt({html: true});
const typescriptLike = /(?:typescript|\b(?:ts|tsx|mts|cts)\b)/i;
const runtimeLike = /(?:\brun\b|\bruntime\b|\bdeno\b|\bbun\b)/i;

/** Extract TypeScript fences using CommonMark, rejecting ambiguous execution declarations. */
export function extractFences(file: string, source: string): Fence[] {
  const lines = source.split(/\r?\n/), fences: Fence[] = [];
  for (const token of markdown.parse(source, {})) {
    if (token.type === "html_block" && /(?:^|\n)\s*(?:> ?)*(?:`{3,}|~{3,})/.test(token.content))
      throw new Error(`${file}: HTML block contains a fence opener`);
    if (token.type !== "fence") continue;
    const language = token.info.trim();
    if (typescriptLike.test(language) && language !== "ts" && language !== "typescript")
      throw new Error(`${file}: invalid TypeScript info string: ${language}`);
    // A literal nested example must not conceal a program from execution.
    if (/^ {0,3}(?:`{3,}|~{3,})(?:ts|typescript|tsx|mts|cts)(?:\b|$)/im.test(token.content))
      throw new Error(`${file}: nested TypeScript fence`);
    const start = token.map![0], end = token.map![1];
    const unwrap = (line: string) => line.replace(/^\s*(?:> ?)+/, "").trim();
    let selected: Runtime = "node", excerpt: "express" | "hono" | undefined;
    const preceding = lines.slice(0, start).map(unwrap).join("\n");
    for (const match of preceding.matchAll(/<!--[\s\S]*?-->/g)) {
      if (preceding.slice(match.index + match[0].length).split("\n").length > 2) continue;
      const comment = match[0];
      if (runtimeLike.test(comment)) {
        if (comment !== "<!-- run: deno -->" && comment !== "<!-- run: bun -->")
          throw new Error(`${file}: invalid runtime annotation: ${comment}`);
        const next = comment === "<!-- run: deno -->" ? "deno" : "bun";
        if (selected !== "node" && selected !== next) throw new Error(`${file}: conflicting runtime annotations`);
        selected = next;
      }
      const annotation = /^<!-- verification-excerpt: (express|hono) -->$/.exec(comment);
      if (annotation) excerpt = annotation[1] as "express" | "hono";
    }
    if (language !== "ts" && language !== "typescript") continue;
    const closing = unwrap(lines[end - 1] ?? "");
    if (!new RegExp(`^${token.markup[0]}{${token.markup.length},}\\s*$`).test(closing))
      throw new Error(`${file}: unclosed TypeScript fence`);
    fences.push({file, index: fences.length + 1, runtime: selected, source: token.content.replace(/\n$/, ""), ...(excerpt ? {excerpt} : {})});
  }
  return fences;
}

/** Collect every repository Markdown file except the changelog and dependencies. */
export function documentationFences(root = process.cwd()): Fence[] {
  const files: string[] = [];
  // Include tracked documents and visible additions; ignore generated output and local hidden directories.
  if (existsSync(join(root, ".git"))) {
    files.push(...execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "--exclude=.[!.]*/", "--", "*.md"], {cwd: root, encoding: "utf8"}).trim().split("\n").filter(Boolean));
  } else {
    const walk = (directory: string) => {
      for (const entry of readdirSync(join(root, directory), {withFileTypes: true})) {
        if (entry.name === "node_modules") continue;
        const file = join(directory, entry.name);
        if (entry.isDirectory()) walk(file);
        else if (entry.isFile() && entry.name.endsWith(".md")) files.push(file);
      }
    };
    walk("");
  }
  const fences = files.sort().filter(file => file !== "CHANGELOG.md" && !file.split("/").includes("node_modules"))
    .flatMap(file => extractFences(file, readFileSync(join(root, file), "utf8")));
  return fences.map(fence => {
    if (!fence.excerpt) return fence;
    const complete = fences.find(candidate => candidate.file === fence.file && !candidate.excerpt && candidate.runtime === fence.runtime && candidate.source.includes("// ---- Your server:"));
    const excerpt = complete && /\/\/ ---- Your server:[^\n]*\n([\s\S]*?)\n\/\/ ---- End of the verification code ----/.exec(complete.source)?.[1];
    if (!complete || excerpt !== fence.source) throw new Error(`${fence.file}: ${fence.excerpt} excerpt differs from its complete program`);
    return {...fence, completeSource: complete.source};
  });
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
    await writeFile(program, (fence.completeSource ?? fence.source) + trailingSource);
    const command = fence.runtime === runtime ? process.execPath : fence.runtime;
    const args = fence.runtime === "node" ? ["--unhandled-rejections=strict", "--experimental-strip-types", "--no-warnings", program]
      : fence.runtime === "deno" ? ["run", "--no-check", `--allow-read=${process.cwd()}`, "--allow-net=127.0.0.1,jsr.io", "--node-modules-dir=manual", program] : ["run", program];
    const env = fence.runtime === "deno"
      ? Object.fromEntries(["PATH", "HOME", "DENO_DIR", "XDG_CACHE_HOME", "SYSTEMROOT"].flatMap(name => process.env[name] === undefined ? [] : [[name, process.env[name]!]]))
      : {...process.env};
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
