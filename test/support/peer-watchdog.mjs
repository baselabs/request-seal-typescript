import {spawn} from 'node:child_process';
import {appendFileSync} from 'node:fs';

// Run in the owned group. Parent death must also end startup and compilation.
const [owner, command, ...args] = process.argv.slice(2);
const child = spawn(command, args, {stdio: 'inherit'});
if (process.env.REQUESTSEAL_PEER_LEDGER && child.pid) appendFileSync(process.env.REQUESTSEAL_PEER_LEDGER, JSON.stringify({pid: child.pid, group: process.pid}) + '\n');
let stopping = false;
const stop = () => {
  if (stopping) return;
  stopping = true;
  try {process.kill(-process.pid, 'SIGTERM');} catch {child.kill('SIGTERM');}
  setTimeout(() => {try {process.kill(-process.pid, 'SIGKILL');} catch {process.exit(1);}}, 1000);
};
process.on('SIGTERM', () => {});
const watch = setInterval(() => {
  if (process.ppid !== Number(owner)) {stop(); return;}
  try {process.kill(Number(owner), 0);} catch {stop();}
}, 100);
child.on('error', error => {console.error(error.message); clearInterval(watch); process.exitCode = 1;});
child.on('close', code => {clearInterval(watch); process.exitCode = code ?? 1;});
