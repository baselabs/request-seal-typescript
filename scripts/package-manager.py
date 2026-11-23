"""Read npm from package.json and require every workspace to declare it."""
import json
import re
from pathlib import Path


def read_npm(manifest):
    manager = json.loads(manifest).get('packageManager', '')
    npm = re.fullmatch(r'npm@(\d+\.\d+\.\d+)', manager) if isinstance(manager, str) else None
    if not npm:
        raise ValueError('package.json must declare an exact npm packageManager')
    return npm[1]


def check_managers(root):
    npm = read_npm((root / 'package.json').read_text())
    for relative in ('interop/package.json', 'interop/adapters/package.json',
                     'interop/browser/package.json', 'interop/migration/package.json',
                     'interop/reciprocal/package.json'):
        if read_npm((root / relative).read_text()) != npm:
            raise ValueError(f'{relative} must declare npm@{npm}')
    return npm


if __name__ == '__main__':
    print(f'npm={check_managers(Path("."))}')
