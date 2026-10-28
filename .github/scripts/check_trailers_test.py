#!/usr/bin/env python3
"""Self-test for check-trailers.py: a scratch repo with good and bad commits.

Every forbidden form is caught (by the rule that names it) and every allowed form
passes, through the real script, real git history and the real environment
variables. Run: python3 .github/scripts/check_trailers_test.py
"""
import os
import subprocess
import sys
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check-trailers.py")

CLOUD = "Co-Authored-By: ukubi-claude-cloud <noreply@bnei.dev>"
SESSION = "Agent-Session: session_016zBNgNf4m4LsxnZ8Mn59Dw"

# (label, message body, rule that must fire under each policy, or None)
# The rule is matched by a fragment of its printed name.
CASES = [
    # allowed under agent
    ("human, no trailers", "feat: x", {"agent": None, "none": None}),
    ("cloud agent", "feat: x\n\n%s\n%s" % (CLOUD, SESSION), {"agent": None, "none": "Co-Authored-By"}),
    ("laptop agent", "feat: x\n\nCo-Authored-By: ukubi-claude-macbook-pro.local <noreply@bnei.dev>", {"agent": None, "none": "Co-Authored-By"}),
    ("fleet agent", "feat: x\n\nCo-Authored-By: ukubi-agent <noreply@bnei.dev>\nAgent-Session: abc123", {"agent": None, "none": "Co-Authored-By"}),
    ("fleet definition", "feat: x\n\nAgent-Definition: reviewer@0123abc", {"agent": None, "none": None}),
    ("human co-author", "feat: x\n\nCo-Authored-By: Jane Doe <jane@example.com>", {"agent": None, "none": "Co-Authored-By"}),
    ("session alone", "feat: x\n\n" + SESSION, {"agent": None, "none": "Agent-Session"}),
    ("env and host names are not model names", "fix: CLAUDE_MODEL and CLAUDE_CODE_OAUTH_TOKEN stay; ukubi-claude-cloud too", {"agent": None, "none": None}),
    ("a host named after a model family", "feat: x\n\nCo-Authored-By: ukubi-claude-sonnet <noreply@bnei.dev>", {"agent": None, "none": "Co-Authored-By"}),
    ("the word opus or a plain claude", "docs: the magnum opus of claude's friend", {"agent": None, "none": None}),
    # refused under agent (and none)
    ("co-author Claude", "feat: x\n\nCo-Authored-By: Claude <noreply@anthropic.com>", {"agent": "names Claude", "none": "Co-Authored-By"}),
    ("co-author model name", "feat: x\n\nCo-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>", {"agent": "names Claude", "none": "Co-Authored-By"}),
    ("co-author Claude at bnei.dev", "feat: x\n\nCo-Authored-By: Claude <noreply@bnei.dev>", {"agent": "names Claude", "none": "Co-Authored-By"}),
    ("co-author anthropic email only", "feat: x\n\nCo-Authored-By: Bot <noreply@anthropic.com>", {"agent": "names Claude", "none": "Co-Authored-By"}),
    ("co-author lower case key", "feat: x\n\nco-authored-by: Claude <c@x.y>", {"agent": "names Claude", "none": "Co-Authored-By"}),
    ("co-author ukubi-claude with an anthropic email", "feat: x\n\nCo-Authored-By: ukubi-claude-cloud <noreply@anthropic.com>", {"agent": "names Claude", "none": "Co-Authored-By"}),
    ("Claude-Session", "feat: x\n\nClaude-Session: https://example.org/s/1", {"agent": "Claude-Session", "none": "Claude-Session"}),
    ("Claude-Session id", "feat: x\n\nclaude-session: abc", {"agent": "Claude-Session", "none": "Claude-Session"}),
    ("generated with", "feat: x\n\n\U0001F916 Generated with something", {"agent": "generated-with", "none": "generated-with"}),
    ("generated  with, lower", "feat: x\n\ngenerated  with a tool", {"agent": "generated-with", "none": "generated-with"}),
    ("claude.ai URL", "feat: x\n\nsee https://claude.ai/code/session_1", {"agent": "URL", "none": "URL"}),
    ("claude.com URL", "feat: x\n\nsee https://www.claude.com/x", {"agent": "URL", "none": "URL"}),
    ("claude.ai without scheme", "feat: x\n\nsee claude.ai/code", {"agent": "URL", "none": "URL"}),
    ("model claude-opus id", "feat: x\n\nmodel claude-opus-5-5 wrote it", {"agent": "model name", "none": "model name"}),
    ("model claude-sonnet id", "feat: x\n\nclaude-sonnet-4-5", {"agent": "model name", "none": "model name"}),
    ("model claude-haiku id", "feat: x\n\nclaude-haiku-4", {"agent": "model name", "none": "model name"}),
    ("model claude-fable id", "feat: x\n\nclaude-fable-1", {"agent": "model name", "none": "model name"}),
    ("model old style id", "feat: x\n\nclaude-3-5-sonnet-20241022", {"agent": "model name", "none": "model name"}),
    ("model Opus 5", "feat: x\n\nwritten by Opus 5", {"agent": "model name", "none": "model name"}),
    ("model Sonnet 4", "feat: x\n\nSonnet 4 did it", {"agent": "model name", "none": "model name"}),
    ("model Claude Sonnet 5.5", "feat: x\n\nClaude Sonnet 5.5", {"agent": "model name", "none": "model name"}),
    ("model Haiku 4.5", "feat: x\n\nhaiku-4.5", {"agent": "model name", "none": "model name"}),
    # the subject line is scanned too
    ("subject", "feat: add Opus 5 support", {"agent": "model name", "none": "model name"}),
]


def git(cwd, *args, env=None):
    e = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.org", GIT_COMMITTER_NAME="t",
             GIT_COMMITTER_EMAIL="t@example.org", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
    if env:
        e.update(env)
    return subprocess.run(["git", *args], cwd=cwd, env=e, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE).stdout.decode().strip()


def run(cwd, policy, rng=None, title=None, body=None):
    env = {k: v for k, v in os.environ.items() if k not in ("PR_TITLE", "PR_BODY")}
    if title is not None:
        env["PR_TITLE"] = title
    if body is not None:
        env["PR_BODY"] = body
    cmd = [sys.executable, "-I", SCRIPT, "--policy", policy]
    if rng:
        cmd += ["--range", rng]
    p = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout.decode()


class Trailers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.repo = cls.tmp.name
        git(cls.repo, "init", "-q", "-b", "main")
        git(cls.repo, "commit", "-q", "--allow-empty", "-m", "chore: base")
        cls.base = git(cls.repo, "rev-parse", "HEAD")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def commit_one(self, msg):
        """One commit on top of base; returns (sha, base..sha)."""
        git(self.repo, "checkout", "-q", "--detach", self.base)
        git(self.repo, "commit", "-q", "--allow-empty", "-m", msg)
        sha = git(self.repo, "rev-parse", "HEAD")
        return sha, "%s..%s" % (self.base, sha)

    def test_each_form_in_a_commit(self):
        for label, msg, want in CASES:
            sha, rng = self.commit_one(msg)
            for policy, rule in want.items():
                with self.subTest(form=label, policy=policy):
                    rc, out = run(self.repo, policy, rng=rng)
                    if rule is None:
                        self.assertEqual(rc, 0, out)
                        self.assertIn("clean", out)
                    else:
                        self.assertEqual(rc, 1, out)
                        self.assertIn(rule, out)
                        self.assertIn(sha[:12], out)  # the offending line carries its commit

    def test_each_form_in_the_pr_body(self):
        for label, msg, want in CASES:
            for policy, rule in want.items():
                with self.subTest(form=label, policy=policy):
                    rc, out = run(self.repo, policy, body=msg)
                    if rule is None:
                        self.assertEqual(rc, 0, out)
                    else:
                        self.assertEqual(rc, 1, out)
                        self.assertIn(rule, out)
                        self.assertIn("PR body", out)

    def test_each_form_in_the_pr_title(self):
        # a title is one line: only the case whose offence is the subject fires
        for label, msg, want in CASES:
            subject = msg.split("\n", 1)[0]
            for policy, rule in want.items():
                with self.subTest(form=label, policy=policy):
                    rc, out = run(self.repo, policy, title=subject)
                    if label == "subject":
                        self.assertEqual(rc, 1, out)
                        self.assertIn("PR title", out)
                    else:
                        self.assertEqual(rc, 0, out)

    def test_offending_commit_is_named_among_clean_ones(self):
        git(self.repo, "checkout", "-q", "--detach", self.base)
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "feat: one\n\n%s\n%s" % (CLOUD, SESSION))
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "fix: two\n\nGenerated with a tool")
        bad = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "feat: three")
        head = git(self.repo, "rev-parse", "HEAD")
        rc, out = run(self.repo, "agent", rng="%s..%s" % (self.base, head))
        self.assertEqual(rc, 1, out)
        self.assertEqual(out.count(bad[:12]), 1, out)
        self.assertNotIn("feat: one", out)

    def test_commits_outside_the_range_are_not_scanned(self):
        git(self.repo, "checkout", "-q", "--detach", self.base)
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "old\n\nClaude-Session: x")
        mid = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "feat: new")
        head = git(self.repo, "rev-parse", "HEAD")
        rc, out = run(self.repo, "agent", rng="%s..%s" % (mid, head))
        self.assertEqual(rc, 0, out)

    def test_merge_commit_messages_are_scanned(self):
        git(self.repo, "checkout", "-q", "--detach", self.base)
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "feat: side")
        side = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "checkout", "-q", "--detach", self.base)
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "feat: main side")
        git(self.repo, "merge", "-q", "--no-ff", "-m", "Merge\n\nClaude-Session: x", side)
        head = git(self.repo, "rev-parse", "HEAD")
        rc, out = run(self.repo, "agent", rng="%s..%s" % (self.base, head))
        self.assertEqual(rc, 1, out)

    def test_pr_text_is_never_interpreted(self):
        # shell metacharacters and workflow commands in the body are plain text
        rc, out = run(self.repo, "agent", body="$(touch pwned)\n`touch pwned`\n::error::x\nCo-Authored-By: Claude <a@b.c>")
        self.assertEqual(rc, 1, out)
        self.assertFalse(os.path.exists(os.path.join(self.repo, "pwned")))
        self.assertFalse(any(l.startswith("::") for l in out.split("\n")), out)

    def test_a_carriage_return_cannot_start_a_log_command(self):
        rc, out = run(self.repo, "agent", body="Generated with x\r::error::boom")
        self.assertEqual(rc, 1, out)
        self.assertNotIn("\r", out)

    def test_title_and_body_together_and_crlf(self):
        rc, out = run(self.repo, "agent", title="feat: fine", body="line\r\nGenerated with x\r\n")
        self.assertEqual(rc, 1, out)
        self.assertIn("PR body", out)
        self.assertNotIn("PR title", out)

    def test_an_empty_range_is_clean(self):
        rc, out = run(self.repo, "agent", rng="%s..%s" % (self.base, self.base))
        self.assertEqual(rc, 0, out)

    def test_usage_errors_fail_closed(self):
        rc, out = run(self.repo, "agent")  # nothing to scan: a misconfigured job must not pass silently
        self.assertNotEqual(rc, 0, out)
        rc, out = run(self.repo, "agent", rng="HEAD~1..HEAD")  # not full shas
        self.assertNotEqual(rc, 0, out)
        rc, out = run(self.repo, "agent", rng="%s..%s" % ("0" * 40, self.base))  # unknown sha: git fails
        self.assertNotEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main(verbosity=1)
