import {spawnSync, execFileSync} from 'node:child_process';

type Options = {env: NodeJS.ProcessEnv; encoding: 'utf8'; cwd?: string; timeout?: number};
type Output = {status: number | null; stdout: string; stderr: string; error?: Error};
type NativeCommand = new (command: string, options: {
  args: string[]; env: Record<string, string>; clearEnv: true;
  stdout: 'piped'; stderr: 'piped'; cwd?: string;
}) => {outputSync: () => {code: number; stdout: Uint8Array; stderr: Uint8Array}};

/** Launch a real child with exactly the selected environment. */
export function spawnWithEnvSync(command: string, args: string[], options: Options): Output {
  const native = (globalThis as unknown as {Deno?: {Command: NativeCommand}}).Deno;
  if (!native) return spawnSync(command, args, options);
  // Deno's Node compatibility merges omitted parent keys. Native clearEnv keeps
  // deletions real; PATH, HOME, and other required keys come from the caller.
  // Like Deno's spawnSync, outputSync does not enforce the Node timeout option.
  const env = Object.fromEntries(Object.entries(options.env).filter((pair): pair is [string, string] => typeof pair[1] === 'string'));
  try {
    const result = new native.Command(command, {
      args, env, clearEnv: true, stdout: 'piped', stderr: 'piped',
      ...(options.cwd === undefined ? {} : {cwd: options.cwd}),
    }).outputSync();
    return {status: result.code, stdout: new TextDecoder().decode(result.stdout), stderr: new TextDecoder().decode(result.stderr)};
  } catch (error) {
    return {status: null, stdout: '', stderr: '', error: error instanceof Error ? error : new Error(String(error))};
  }
}

export function execFileWithEnvSync(command: string, args: string[], options: Options): string {
  if (!process.versions.deno) return execFileSync(command, args, options);
  const result = spawnWithEnvSync(command, args, options);
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Child exit ${result.status}: ${result.stdout}${result.stderr}`);
  return result.stdout;
}
