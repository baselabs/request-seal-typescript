type Test = {name: string; run: () => unknown};
const tests: Test[] = [];
export type Summary = {passed: number; failed: number; total: number; failures: {name: string; message: string}[]};
export default function test(name: string, run: () => unknown): void {
  if (tests.some(t => t.name === name)) throw new Error('Duplicate browser test title: ' + name);
  tests.push({name, run});
}
export async function run(): Promise<Summary> {
  const failures: Summary['failures'] = [];
  let passed = 0;
  for (const t of tests) {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        Promise.resolve().then(t.run),
        new Promise<never>((_, reject) => {timer = setTimeout(() => reject(new Error('Browser test exceeded 30 seconds')), 30000);}),
      ]);
      console.log('REQUEST_SEAL_TEST ' + JSON.stringify({name: t.name, passed: true}));
      passed++;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Test threw a non-Error';
      failures.push({name: t.name, message});
      console.log('REQUEST_SEAL_TEST ' + JSON.stringify({name: t.name, passed: false, message}));
      // A timeout leaves work running: stop this page instead of overlapping tests.
      if (message === 'Browser test exceeded 30 seconds') break;
    } finally { clearTimeout(timer); }
  }
  const summary = {passed, failed: failures.length, total: passed + failures.length, failures};
  console.log('REQUEST_SEAL_RESULT ' + JSON.stringify(summary));
  return summary;
}
