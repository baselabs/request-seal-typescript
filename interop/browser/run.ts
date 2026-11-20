import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {selectRuntimeLimits, type RuntimeLimit} from '../../tools/conformance/runtime-limits.ts';
import {chromium, firefox, webkit, type BrowserType} from 'playwright';
import {serve} from './server.ts';
import {limitRecords} from './records.ts';
import {portableFiles} from './selection.ts';
import type {Summary} from './harness.ts';

async function main(): Promise<void> {
  const red = process.argv.includes('--red');
  const table = JSON.parse(readFileSync(new URL('../../tools/conformance/runtime-limits.json', import.meta.url), 'utf8'));
  // Validate the complete declaration before selecting a browser release.
  selectRuntimeLimits(table, process.versions);
  const platform = `${process.platform}-${process.arch}`;
  const requested = process.argv.filter(a => a.startsWith('--browser=')).map(a => a.slice('--browser='.length));
  const engines: Record<string, BrowserType> = {chromium, firefox, webkit};
  for (const name of requested) assert.ok(Object.hasOwn(engines, name), 'Unknown browser: ' + name);
  let failures = 0;
  const redOutput: string[] = [];
  // A partial red run must not satisfy the shared marker/count check.
  const output = (line: string) => red ? redOutput.push(line) : console.log(line);
  const failed = (browser: string, mode: string, error: unknown) => {
    failures++;
    console.error(JSON.stringify({browser, mode, status: 'failed', error: error instanceof Error ? error.message : 'Unknown runner failure'}));
  };
  const server = await serve();
  try {
    for (const [name, engine] of Object.entries(engines)) {
      if (requested.length && !requested.includes(name)) continue;
      let browser;
      try {browser = await engine.launch();} catch (error) {failed(name, 'launch', error); continue;}
      try {
        assert.ok(Object.hasOwn(table[name] ?? {}, browser.version()), `Browser release ${browser.version()} must match the declared CI matrix`);
        const modes = red ? [true] : [false, true];
        for (const planted of modes) {
          const context = await browser.newContext();
          try {
          // Real delivery probes also use a closed loopback port and RFC 6761's
          // reserved .invalid name. Continue these requests to the real runtime;
          // aborting them here would replace the transport failure under test.
          await context.route('**/*', route => {
            const url = new URL(route.request().url());
            const allowed = url.origin === new URL(server.url).origin || url.origin === server.closedOrigin || server.deliveryOrigins.has(url.origin) ||
              url.origin === 'http://delivery-canary.invalid';
            return allowed ? route.continue() : route.abort();
          });
          const page = await context.newPage();
          let result: Summary | undefined;
          let files: string[] | undefined;
          const limits: readonly RuntimeLimit[] = (table[name]?.[browser.version()] ?? []).filter((entry: {platforms?: string[]}) => !entry.platforms || entry.platforms.includes(platform));
          // This WebKit diagnostic is emitted to Playwright rather than the page.
          const corsDiagnostics = !planted && name === 'webkit' && limits.find(entry => entry.id === 'fetch/cors_diagnostics');
          const pageLimits = limits.filter(entry => entry.id !== 'fetch/cors_diagnostics');
          const probeUrls = [server.closedOrigin + '/', 'http://delivery-canary.invalid/'];
          // Playwright's WebKit _onConsoleMessage splits the native message at
          // http:; the resulting Error.message starts at /host (v1.64.1 wkPage.ts).
          const accessControlProbes = new Map(probeUrls.map(url =>
            [url.slice('http:/'.length) + ' due to access control checks.', url] as const));
          const failedProbes = new Set<string>(), accessControlMessages: string[] = [];
          const observed: {id: string; observed: string}[] = [];
          const records: {name: string; passed: boolean; message?: string}[] = [];
          const fatal: string[] = [];
          page.on('requestfailed', request => {
            if (probeUrls.includes(request.url())) failedProbes.add(request.url());
          });
          page.on('pageerror', error => {
            if (corsDiagnostics && accessControlProbes.has(error.message)) accessControlMessages.push(error.message);
            else fatal.push(error.message);
          });
          page.on('console', message => {
            const line = message.text();
            try {
            if (line.startsWith('REQUEST_SEAL_FILES ')) {assert.equal(files, undefined); files = JSON.parse(line.slice(19));}
            if (line.startsWith('REQUEST_SEAL_LIMIT ')) {observed.push(JSON.parse(line.slice(19))); output(`${name}: ${line}`);}
            if (line.startsWith('REQUEST_SEAL_TEST ')) {records.push(JSON.parse(line.slice(18))); output(`${name}: ${line}`);}
            if (line.startsWith('REQUEST_SEAL_RESULT ')) {
              assert.equal(result, undefined, 'Only one browser summary is allowed');
              result = JSON.parse(line.slice(20));
            }
            if (line.startsWith('REQUEST_SEAL_FATAL ')) fatal.push(line);
            } catch (error) {fatal.push(error instanceof Error ? error.message : 'Invalid console record');}
          });
          await page.goto(server.url + '?' + new URLSearchParams(planted ? {red: '1'} : {limits: JSON.stringify(pageLimits)}));
          await page.waitForFunction("document.documentElement.dataset.complete === 'true'", undefined, {timeout: 180000});
          if (corsDiagnostics) {
            assert.deepEqual(accessControlMessages.sort(), [...accessControlProbes.keys()].sort(), 'Both real network probes must produce the declared WebKit diagnostics');
            for (const url of probeUrls) assert.ok(failedProbes.has(url), 'A diagnostic must correspond to an actual failed request: ' + url);
            assert.deepEqual(corsDiagnostics.items, [1]);
            const record = {id: 'fetch/cors_diagnostics', observed: 'browser/access_control_diagnostic'};
            assert.equal(corsDiagnostics.observed, record.observed);
            observed.push(record);
            output(`${name}: REQUEST_SEAL_LIMIT ${JSON.stringify(record)}`);
          }
          assert.deepEqual(fatal, []);
          assert.ok(result, `${name}: browser page must report executed test counts`);
          assert.equal(records.length, result.total, 'Console results must tie out with summary');
          assert.equal(records.filter(r => r.passed).length, result.passed);
          assert.equal(records.filter(r => !r.passed).length, result.failed);
          if (planted) {
            assert.equal(result.total, 1);
            assert.equal(result.failed, 1);
            assert.equal(result.passed, 0);
            assert.match(result.failures[0]!.message, /Intentional red proof/);
          } else {
            assert.deepEqual(files, [...portableFiles], 'Every pinned portable file must load');
            assert.ok(result.total > portableFiles.length, 'The pinned files must register their tests');
            assert.equal(result.failed, 0, JSON.stringify(result.failures));
            assert.deepEqual(limitRecords(observed), limitRecords(limits), 'Every declared limitation must execute with its exact reason');
            assert.ok(records.some(r => r.passed && r.name.startsWith('browser Fetch verification refuses')));
          }
          output(JSON.stringify({browser: name, version: browser.version(), platform, limitations: planted ? [] : observed, mode: planted ? 'red' : 'green', ...result}));
          if (planted) output(`# fail ${result.failed}`);
          } catch (error) {failed(name, planted ? 'red' : 'green', error);}
          finally {await context.close();}
        }
      } catch (error) {failed(name, 'context', error);}
      finally {await browser.close();}
    }
    if (red && failures === 0) for (const line of redOutput) console.log(line);
    if (red || failures > 0) process.exitCode = 1;
  } finally {await server.close();}
}
main().catch(error => {console.error(error); process.exitCode = 1;});
