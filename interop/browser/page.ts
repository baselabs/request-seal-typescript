import {run, default as test} from './harness.ts';
import {assertAllObserved} from './limits.ts';
async function main(): Promise<void> {
  if (new URL(location.href).searchParams.has('red')) await import('./.generated/planted.test.ts');
  else {
    const {files} = await import('./.generated/index.ts');
    console.log('REQUEST_SEAL_FILES ' + JSON.stringify(files));
    await import('./cases.ts');
    const {registerFetchTests} = await import('./fetch.ts');
    registerFetchTests(location.origin);
    test('every declared browser limitation executed', assertAllObserved);
  }
  await run();
  document.documentElement.dataset.complete = 'true';
}
main().catch(error => {
  console.error('REQUEST_SEAL_FATAL ' + (error instanceof Error ? error.message : 'Unknown page failure'));
  document.documentElement.dataset.complete = 'true';
});
