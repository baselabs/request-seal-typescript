"""Read the exact toolchain declarations used by every hosted workflow."""
import json
import re
from pathlib import Path


def read_versions(source):
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
        versions[name] = values
    required = {'nodejs', 'nodejs-compat', 'npm', 'deno', 'deno-os-trust', 'bun', 'elixir', 'erlang'}
    if versions.keys() != required:
        raise ValueError('tool declarations must match the hosted toolchain inventory')
    if any(len(values) != 1 for name, values in versions.items() if name != 'nodejs-compat'):
        raise ValueError('only nodejs-compat may declare multiple versions')
    nodes = [*versions['nodejs-compat'], versions['nodejs'][0]]
    if len(nodes) != len(set(nodes)):
        raise ValueError('duplicate Node compatibility lane')
    if versions['elixir'][0].split('-otp-')[1] != versions['erlang'][0].split('.')[0]:
        raise ValueError('Elixir and OTP declarations differ')
    return {name: values[0] for name, values in versions.items() if name != 'nodejs-compat'} | {
        'nodes': sorted(nodes, key=lambda value: tuple(map(int, value.split('.')))),
        'native': [{'runtime': name, 'version': versions[name][0]} for name in ('deno', 'bun')],
    }


if __name__ == '__main__':
    for key, value in read_versions(Path('.tool-versions').read_text()).items():
        print(f'{key}={json.dumps(value, separators=(",", ":")) if isinstance(value, list) else value}')
