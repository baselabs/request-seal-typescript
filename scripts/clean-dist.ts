import {rmSync} from 'node:fs';
// The build owns dist. Remove stale compiler output before emitting current sources.
rmSync(new URL('../dist/', import.meta.url), {recursive: true, force: true});
