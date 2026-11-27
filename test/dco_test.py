"""Exercise the qualification check against real, disposable Git histories."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECKER = Path(__file__).resolve().parents[1] / 'scripts/check-dco.py'


class DcoTest(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix='request-seal-dco-')
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name) / 'history'
        self.root.mkdir()
        self.git('init', '--quiet', '--initial-branch=main')
        self.git('config', 'user.name', 'Example Contributor')
        self.git('config', 'user.email', 'contributor@example.com')
        self.git('config', 'commit.gpgsign', 'false')
        self.legacy = self.commit('Before the policy')

    def git(self, *args):
        return subprocess.check_output(
            ['git', *args], cwd=self.root, text=True, timeout=10
        ).strip()

    def commit(self, message, *, signed=False):
        signoff = ['--signoff'] if signed else []
        self.git('commit', '--quiet', '--allow-empty', *signoff, '-m', message)
        return self.git('rev-parse', 'HEAD')

    def introduce_policy(self, *, signed=True):
        (self.root / 'IPR.md').write_text('# Intellectual property\n', encoding='utf-8')
        self.git('add', 'IPR.md')
        return self.commit('Adopt the policy', signed=signed)

    def check(self, root=None):
        return subprocess.run(
            [sys.executable, '-I', '-B', str(CHECKER)],
            cwd=root or self.root, text=True, capture_output=True, timeout=10,
        )

    def assert_refused(self, *commits):
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stderr)
        for commit in commits:
            self.assertIn(f'{commit}: missing a valid Signed-off-by trailer', result.stderr)
        self.assertNotIn(self.legacy, result.stderr)

    def test_signed_policy_and_descendants_pass_with_unsigned_legacy_history(self):
        self.introduce_policy()
        self.commit('Signed change', signed=True)
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unsigned_introduction_is_refused_even_with_signed_head(self):
        introduction = self.introduce_policy(signed=False)
        self.commit('Signed change', signed=True)
        self.assert_refused(introduction)

    def test_body_example_and_malformed_trailer_do_not_count(self):
        self.introduce_policy()
        example = self.commit('Explain sign-off\n\nSigned-off-by: Example Contributor '
                              '<contributor@example.com>\n\nThis was an example.')
        malformed = self.commit('Malformed trailer\n\nSigned-off-by: Example Contributor')
        self.commit('Signed change', signed=True)
        self.assert_refused(example, malformed)

    def test_unsigned_merged_commit_is_refused_even_with_signed_merge(self):
        self.introduce_policy()
        self.git('checkout', '--quiet', '-b', 'topic')
        topic = self.commit('Unsigned topic')
        self.git('checkout', '--quiet', 'main')
        self.commit('Signed main change', signed=True)
        self.git('merge', '--quiet', '--no-ff', '--no-edit', '--signoff', 'topic')
        self.assert_refused(topic)

    def test_missing_policy_and_shallow_history_are_refused(self):
        missing = self.check()
        self.assertEqual(missing.returncode, 1)
        self.assertIn('could not find the commit introducing IPR.md', missing.stderr)
        self.introduce_policy()
        shallow = self.root.parent / 'shallow'
        self.git('clone', '--quiet', '--depth=1', self.root.as_uri(), str(shallow))
        result = self.check(shallow)
        self.assertEqual(result.returncode, 1)
        self.assertIn('requires full Git history', result.stderr)
