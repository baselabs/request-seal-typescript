"""Require a DCO sign-off from the introduction of IPR.md onward."""
import re
import subprocess
import sys


def git(*args):
    return subprocess.check_output(
        ['git', '--no-replace-objects', *args], encoding='utf-8',
    )


def main():
    if git('rev-parse', '--is-shallow-repository').strip() != 'false':
        sys.exit('DCO check requires full Git history')

    introductions = git(
        'log', '--first-parent', '--diff-merges=first-parent', '--no-renames',
        '--diff-filter=A', '--reverse', '--no-show-signature', '--format=%H',
        'HEAD', '--', 'IPR.md',
    ).splitlines()
    if not introductions:
        sys.exit('DCO check could not find the commit introducing IPR.md')

    introduction = introductions[0]
    # Exclude the earlier mainline history. Check the introduction itself and
    # every subsequent commit reachable from HEAD, including merged commits.
    first_parent = git('rev-list', '--parents', '-n', '1', introduction).split()[1:2]
    commits = git('rev-list', 'HEAD', '--not', *first_parent).splitlines()

    identity = re.compile(r'[^<>\r\n]*[^<>\s][ \t]+<[^<>@\s]+@[^<>@\s]+>')
    missing = []
    for commit in commits:
        trailers = git(
            'show', '-s', '--no-show-signature',
            '--format=%(trailers:key=Signed-off-by,valueonly,unfold=true)', commit,
        ).splitlines()
        if not any(identity.fullmatch(value.strip()) for value in trailers):
            missing.append(commit)

    if missing:
        for commit in missing:
            print(f'{commit}: missing a valid Signed-off-by trailer', file=sys.stderr)
        return 1
    print(f'DCO sign-offs verified for {len(commits)} commit(s)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
