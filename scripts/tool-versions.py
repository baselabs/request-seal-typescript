"""Read the exact toolchain declarations used by every hosted workflow.

`.tool-versions` names only real tools, so asdf and mise install it unchanged. A line
may list several exact versions; the first is the primary. Every Node version is a
CI lane. The first Deno version is the supported runtime; each later, newer Deno
version runs only the denied-OS-roots check. Bun, Elixir and Erlang declare one
version each. npm comes from the root manifest's `packageManager`.
"""
import json
import re
from pathlib import Path

TOOLS = ('nodejs', 'deno', 'bun', 'elixir', 'erlang')
SINGLE = ('bun', 'elixir', 'erlang')


def _key(value):
    return tuple(map(int, value.split('.')))


def read_versions(source, manifest):
    versions = {}
    for line in source.splitlines():
        fields = line.split('#', 1)[0].split()
        if not fields:
            continue
        name, *values = fields
        if name in versions or not values:
            raise ValueError(f'duplicate or empty tool declaration: {name}')
        pattern = r'\d+\.\d+\.\d+-otp-\d+' if name == 'elixir' else r'\d+\.\d+\.\d+'
        if any(not re.fullmatch(pattern, value) for value in values):
            raise ValueError(f'non-exact tool version: {name}')
        if len(values) != len(set(values)):
            raise ValueError(f'duplicate version for {name}')
        versions[name] = values
    if versions.keys() != set(TOOLS):
        raise ValueError('tool declarations must match the hosted toolchain inventory')
    if any(len(versions[name]) != 1 for name in SINGLE):
        raise ValueError('bun, elixir and erlang declare exactly one version')
    supported, *probes = versions['deno']
    if not probes or any(_key(probe) <= _key(supported) for probe in probes):
        raise ValueError('deno lists the supported runtime first, then newer denied-roots versions')
    if versions['elixir'][0].split('-otp-')[1] != versions['erlang'][0].split('.')[0]:
        raise ValueError('Elixir and OTP declarations differ')
    manager = json.loads(manifest).get('packageManager', '')
    npm = re.fullmatch(r'npm@(\d+\.\d+\.\d+)', manager)
    if not npm:
        raise ValueError('package.json must declare an exact npm packageManager')
    return {
        'nodejs': versions['nodejs'][0],
        'nodes': sorted(versions['nodejs'], key=_key),
        'npm': npm[1],
        'native': [{'runtime': 'deno', 'version': supported}, {'runtime': 'bun', 'version': versions['bun'][0]}],
        'deno_os_trust': sorted(probes, key=_key),
        'elixir': versions['elixir'][0],
        'erlang': versions['erlang'][0],
    }


if __name__ == '__main__':
    selected = read_versions(Path('.tool-versions').read_text(), Path('package.json').read_text())
    for key, value in selected.items():
        print(f'{key}={json.dumps(value, separators=(",", ":")) if isinstance(value, list) else value}')
