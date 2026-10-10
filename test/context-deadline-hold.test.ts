import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
const prefix = Object.hasOwn(process.versions, 'deno') ? ['eval', '--no-check'] : Object.hasOwn(process.versions, 'bun') ? ['-e'] : ['--experimental-strip-types', '--no-warnings', '--input-type=module', '-e'];
const context = new URL('../src/context.ts', import.meta.url).href;
const result = new URL('../src/result.ts', import.meta.url).href;
const api = new URL('../src/index.ts', import.meta.url).href;
// The watchdog must be unreferenced: only leaked library work can make it fire.
const watchdog = `const dog=setTimeout(()=>{console.log('held');globalThis.Deno?Deno.exit(3):process.exit(3)},2000);globalThis.Deno?Deno.unrefTimer(dog):dog.unref();`;
const setup = `const {withDeadline,run,releaseContext}=await import(${JSON.stringify(context)});const {ok}=await import(${JSON.stringify(result)});${watchdog}const hung=()=>new Promise(()=>{});const print=r=>console.log(r.ok?'ok':r.error.reason);const make=o=>{const r=withDeadline(o);if(!r.ok)throw Error(r.error.reason);return r.value;};`;
function child(name: string, code: string, stdout: string): void {
  test(name, {timeout: 15_000}, () => {
    const env = {...process.env}; delete env.NODE_TEST_CONTEXT;
    const spawned = spawnSync(process.execPath, [...prefix, setup + code], {encoding: 'utf8', timeout: 10_000, env});
    assert.equal(spawned.status, 0, spawned.stderr || String(spawned.error));
    assert.equal(spawned.stdout, stdout + '\n');
  });
}
child('unawaited hung run ends at its deadline', `void run(make({timeoutMs:200}),hung).then(print);console.log('created');`, 'created\ndeadline_exceeded');
child('awaited hung run ends at its deadline', `print(await run(make({timeoutMs:200}),hung));`, 'deadline_exceeded');
child('unawaited public signer ends at its Context deadline', `const {Message,sign}=await import(${JSON.stringify(api)});const m=(await Message.request('GET','https://example.com/',[],null)).value;void sign(m,{label:'s',signatureInput:'("@method")',algorithm:'ed25519'},(_a,_b)=>hung(),{context:make({timeoutMs:200})}).then(print);console.log('created');`, 'created\nsigner_failed');
child('zero-config public signer ends at its signing deadline', `const {Message,sign}=await import(${JSON.stringify(api)});const m=(await Message.request('GET','https://example.com/',[],null)).value;void sign(m,{label:'s',algorithm:'ed25519',components:'("@method")',expiresIn:60},(_a,_b,_c)=>hung(),{clock:()=>10,signingTimeout:200}).then(print);console.log('created');`, 'created\nsigner_failed');
for (const signal of [false, true]) {
  const options = `{timeoutMs:300000${signal ? ',signal:new AbortController().signal' : ''}}`;
  child(`idle Context releases the process ${signal ? 'with' : 'without'} a caller signal (regression guard)`, `make(${options});console.log('created');`, 'created');
  child(`settled run clears its hold ${signal ? 'with' : 'without'} a caller signal (regression guard)`, `print(await run(make(${options}),()=>ok(1)));`, 'ok');
  child(`internal Context release preserves an active hold ${signal ? 'with' : 'without'} a caller signal`, `const c=make({timeoutMs:300${signal ? ',signal:new AbortController().signal' : ''}});void run(c,hung).then(print);setTimeout(()=>releaseContext(c),50);console.log('created');`, 'created\ndeadline_exceeded');
}
child('caller abort settles a hung run and clears its hold (regression guard)', `const caller=new AbortController();const c=make({timeoutMs:300000,signal:caller.signal});void run(c,hung).then(print);setTimeout(()=>caller.abort(),50);console.log('created');`, 'created\ndeadline_exceeded');
child('short child deadline leaves its idle parent alive', `const parent=make({timeoutMs:300000});const c=make({parent,timeoutMs:200});void run(c,hung).then(r=>{print(r);console.log('parent '+parent.signal.aborted)});console.log('created');`, 'created\ndeadline_exceeded\nparent false');
child('nested settlement preserves the outer run hold', `const c=make({timeoutMs:200});void run(c,async()=>{print(await run(c,()=>ok(1)));return hung();}).then(print);console.log('created');`, 'created\nok\ndeadline_exceeded');
child('concurrent settlement preserves the hung run hold', `const c=make({timeoutMs:200});void run(c,hung).then(print);void run(c,()=>ok(1)).then(print);console.log('created');`, 'created\nok\ndeadline_exceeded');
child('early deadline timers rearm until all chained runs settle', `let settled=0;process.on('exit',()=>console.log('settled '+settled+' of 300'));const next=()=>{if(settled===300)return;void run(make({timeoutMs:1+settled%3}),hung).then(r=>{if(r.ok||r.error.reason!=='deadline_exceeded')throw Error('wrong result');settled++;next();});};next();`, 'settled 300 of 300');
for (const reuse of [false, true]) child(`throwing timer reference methods preserve ${reuse ? 'reused' : 'new'} signal Context results`, `if(globalThis.Deno){console.log('SKIP captured numeric timer methods');}else{const sample=setTimeout(()=>{},1000);const proto=Object.getPrototypeOf(sample);clearTimeout(sample);const fail=()=>{throw Error('private timer diagnostic')};${reuse ? `const c=make({timeoutMs:300,signal:new AbortController().signal});print(await run(c,()=>ok(1)));releaseContext(c);proto.ref=fail;proto.unref=fail;` : `proto.ref=fail;proto.unref=fail;const c=make({timeoutMs:200,signal:new AbortController().signal});console.log('made');`}void run(c,hung).then(print,()=>console.log('rejected'));console.log('created');}`, Object.hasOwn(process.versions, 'deno') ? 'SKIP captured numeric timer methods' : reuse ? 'ok\ncreated\ndeadline_exceeded' : 'made\ncreated\ndeadline_exceeded');
