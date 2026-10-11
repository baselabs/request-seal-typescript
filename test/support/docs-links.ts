import { readFile, readdir, stat } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import MarkdownIt from "markdown-it";
import GithubSlugger from "github-slugger";

const markdown = new MarkdownIt({html: true});

/** Recursively collect Markdown documents without following directory symlinks. */
export async function documentationFiles(root = process.cwd()): Promise<string[]> {
  const files = ["README.md", "CONTRIBUTING.md", "SECURITY.md"];
  async function walk(directory: string): Promise<void> {
    for (const entry of await readdir(join(root, directory), {withFileTypes: true})) {
      const file = join(directory, entry.name);
      if (entry.isDirectory()) await walk(file);
      else if (entry.isFile() && entry.name.endsWith(".md")) files.push(file);
    }
  }
  await walk("docs");
  return files.sort();
}

/** GitHub heading anchors, including duplicate headings and explicit HTML anchors. */
function anchors(source: string): Set<string> {
  const tokens = markdown.parse(source, {}), slugger = new GithubSlugger(), found = new Set<string>();
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index]!;
    if (token.type === "heading_open") {
      const heading = tokens[index + 1]!;
      const text = (heading.children ?? []).map(child => ["text", "code_inline"].includes(child.type) ? child.content : child.type === "softbreak" ? " " : child.type === "image" ? child.content : "").join("");
      found.add(slugger.slug(text));
    }
    if (token.type === "html_block" || token.type === "inline") {
      const html = token.type === "inline" ? (token.children ?? []).filter(child => child.type === "html_inline").map(child => child.content).join("\n") : token.content;
      for (const match of html.matchAll(/\b(?:id|name)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) found.add(match[1] ?? match[2]!);
    }
  }
  return found;
}

/** Validate all relative inline, reference, image, and same-document Markdown links. */
export async function checkDocumentationLinks(root = process.cwd()): Promise<{files: number; links: number}> {
  const files = await documentationFiles(root), cache = new Map<string, Set<string>>();
  const failures: string[] = [];
  const directoryEntries = new Map<string, Set<string>>();
  let links = 0;
  for (const file of files) {
    const source = await readFile(join(root, file), "utf8"), destinations: string[] = [];
    const visit = (tokens: ReturnType<MarkdownIt["parse"]>) => {
      for (const token of tokens) {
        const destination = token.type === "link_open" ? token.attrGet("href") : token.type === "image" ? token.attrGet("src") : null;
        if (destination !== null) destinations.push(destination);
        if (token.children) visit(token.children);
      }
    };
    const environment: {references?: Record<string, {href: string}>} = {};
    visit(markdown.parse(source, environment));
    const knownDestinations = new Set(destinations);
    for (const reference of Object.values(environment.references ?? {}))
      if (!knownDestinations.has(reference.href)) { destinations.push(reference.href); knownDestinations.add(reference.href); }
    for (const destination of destinations) {
      if (/^(?:[a-z][a-z\d+.-]*:|\/\/)/i.test(destination)) continue;
      links++;
      try {
        const hash = destination.indexOf("#");
        const path = decodeURIComponent((hash < 0 ? destination : destination.slice(0, hash)).split("?")[0]!);
        const anchor = hash < 0 ? "" : decodeURIComponent(destination.slice(hash + 1));
        const target = path ? path.startsWith("/") ? resolve(root, `.${path}`) : resolve(root, dirname(file), path) : resolve(root, file);
        // Exact component spelling also catches broken GitHub links on a
        // developer filesystem that resolves names without regard to case.
        let directory = resolve(root);
        for (const component of relative(root, target).split(sep)) {
          if (component === "..") { directory = dirname(directory); continue; }
          let entries = directoryEntries.get(directory);
          if (!entries) { entries = new Set(await readdir(directory)); directoryEntries.set(directory, entries); }
          if (!entries.has(component)) throw new Error(`path component ${component} not found with exact case`);
          directory = join(directory, component);
        }
        if (!(await stat(target)).isFile()) throw new Error("target is not a file");
        if (anchor) {
          let headings = cache.get(target);
          if (!headings) { headings = anchors(await readFile(target, "utf8")); cache.set(target, headings); }
          if (!headings.has(anchor)) throw new Error(`heading or anchor #${anchor} not found`);
        }
      } catch (error) { failures.push(`${file}: ${destination}: ${(error as Error).message}`); }
    }
  }
  if (failures.length) throw new Error(failures.join("\n"));
  return {files: files.length, links};
}
