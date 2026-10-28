#!/usr/bin/env python3
"""Refuse commit messages and PR text that carry the wrong AI attribution.

Usage:
  check-trailers.py [--policy agent|none] [--range BASE..HEAD]

  --range   scan every commit message in BASE..HEAD (two full 40-hex shas)
  PR_TITLE, PR_BODY (environment)
            scan the pull request's title and body when set; they come in
            through the environment, never interpolated into a shell script

Policies:
  agent  (default: ukubi-bridge, ukubi-game, ukubi-kit, agent-fleet) an agent's
         commit may carry
             Co-Authored-By: ukubi-claude-<host> <noreply@bnei.dev>
             Co-Authored-By: ukubi-agent <noreply@bnei.dev>
             Agent-Session: <id>        Agent-Definition: <name>@<sha>
         A human co-author passes. A Co-Authored-By naming Claude or Anthropic
         in any other form is refused.
  none   (mountain) no AI trailer at all: no Co-Authored-By, no Agent-Session.

Both policies refuse a "Claude-Session:" trailer, a generated-with footer (a
line that starts with it, or one that goes on to name Claude or Anthropic;
ordinary prose such as "files generated with protoc-gen-go" passes), a claude.ai
or claude.com URL and a model name.

Each commit's author and committer name and email are scanned too: GitHub's
squash merge turns every distinct commit author into a "Co-authored-by:"
trailer on main. Under "agent" an identity naming Claude or Anthropic is refused
unless it is an allowed one (ukubi-claude-<host> or ukubi-agent at
noreply@bnei.dev); under "none" any such identity is refused.

Prints every offending line with its commit sha (or "PR title" / "PR body")
and exits 1 if there is any.
Python 3 standard library only.
"""
import argparse
import os
import re
import subprocess
import sys

I = re.IGNORECASE

CO_AUTHOR = re.compile(r"^\s*co-authored-by\s*:(?P<who>.*)$", I)
ALLOWED_CO_AUTHOR = re.compile(r"^\s*(ukubi-claude-[A-Za-z0-9._-]+|ukubi-agent)\s+<noreply@bnei\.dev>\s*$")
# "ukubi-claude-<host>" and env names such as CLAUDE_MODEL are not model names:
# a model name is claude-<family> or <family> <number>.
# \s also matches a no-break space and the other Unicode spaces; _ is a separator
# too (claude_opus_5).
FAMILY = r"(?:opus|sonnet|haiku|fable)"
MODEL = re.compile(
    r"(?<![A-Za-z0-9])(?<!ukubi-)claude[\s_-](?:\d[\w.-]*[\s_-])?" + FAMILY + r"(?![A-Za-z])"
    r"|(?<![A-Za-z0-9])" + FAMILY + r"[\s_-]?\d",
    I,
)
# A generated-with footer starts its line (after any emoji or markdown), or goes
# on to name Claude or Anthropic. "files generated with protoc-gen-go" is prose.
GENERATED_WITH = re.compile(
    r"^[^A-Za-z0-9]*generated\s+with\b|generated\s+with\s+[^A-Za-z0-9]*(?:claude|anthropic)", I
)
AI_IDENTITY = re.compile(r"claude|anthropic", I)


# A rule is (name, policies it applies to, function(line) -> bool). Add a rule
# here; nothing else changes.
def _co_author_any(line):
    return bool(CO_AUTHOR.match(line))


def _co_author_ai(line):
    m = CO_AUTHOR.match(line)
    if not m:
        return False
    who = m.group("who")
    if ALLOWED_CO_AUTHOR.match(who):
        return False
    return bool(re.search(r"claude|anthropic", who, I))


RULES = [
    ("Co-Authored-By (no AI trailer allowed here)", {"none"}, _co_author_any),
    ("Co-Authored-By names Claude or Anthropic", {"agent"}, _co_author_ai),
    ("Agent-Session (no AI trailer allowed here)", {"none"}, lambda l: bool(re.match(r"^\s*agent-session\s*:", l, I))),
    ("Claude-Session trailer", {"agent", "none"}, lambda l: bool(re.match(r"^\s*claude-session\s*:", l, I))),
    ("generated-with footer", {"agent", "none"}, lambda l: bool(GENERATED_WITH.search(l))),
    ("claude.ai / claude.com URL", {"agent", "none"}, lambda l: bool(re.search(r"(?<![A-Za-z0-9-])claude\.(?:ai|com)(?![A-Za-z0-9-])", l, I))),
    ("model name", {"agent", "none"}, lambda l: bool(MODEL.search(l))),
]


def offences(text, policy):
    """Yield (rule name, line) for every offending line of one message."""
    # splitlines, not split("\n"): a bare CR, U+2028 or a vertical tab starts a
    # line for a Markdown renderer too, so it must not hide a trailer.
    for line in text.splitlines():
        for name, policies, hit in RULES:
            if policy in policies and hit(line):
                yield name, line


def identity_offences(ident, policy):
    """Yield (rule name, identity) when a commit's author or committer names an AI."""
    if not AI_IDENTITY.search(ident):
        return
    if policy == "agent" and ALLOWED_CO_AUTHOR.match(ident):
        return
    yield "author/committer identity names Claude or Anthropic", ident


def git_out(*args):
    return subprocess.run(["git", *args], check=True, stdout=subprocess.PIPE).stdout.decode("utf-8", "replace")


def commits(rng):
    """Yield (short sha, message, [identity, ...]) for every commit of BASE..HEAD.

    The shas are listed first and each commit is read on its own, so no byte of a
    message (a \\x1e, say) can split one record into two.
    """
    base, _, head = rng.partition("..")
    for sha in (base, head):
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            sys.exit("check-trailers: --range wants two full 40-hex shas, got %r" % rng)
    for sha in git_out("rev-list", "%s..%s" % (base, head), "--").split():
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            sys.exit("check-trailers: git rev-list gave %r, not a sha" % sha)
        body = git_out("log", "-1", "--format=%B", sha, "--")
        an, ae, cn, ce = git_out("log", "-1", "--format=%an%x00%ae%x00%cn%x00%ce", sha, "--").rstrip("\n").split("\x00")
        yield sha[:12], body, ["%s <%s>" % (an, ae), "%s <%s>" % (cn, ce)]


def show(line):
    # One physical line, no control characters: a log line must not be able to
    # start a workflow command.
    line = "".join(c if c.isprintable() else "?" for c in line.strip())
    return line if len(line) <= 200 else line[:200] + "..."


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--policy", choices=["agent", "none"], default="agent")
    ap.add_argument("--range")
    args = ap.parse_args(argv)

    messages = []
    identities = []
    if args.range:
        for sha, body, idents in commits(args.range):
            messages.append((sha, body))
            identities += [(sha, i) for i in dict.fromkeys(idents)]
    for label, var in (("PR title", "PR_TITLE"), ("PR body", "PR_BODY")):
        if os.environ.get(var):
            messages.append((label, os.environ[var]))
    if not args.range and not messages:
        sys.exit("check-trailers: nothing to scan (give --range and/or PR_TITLE / PR_BODY)")

    bad = 0
    for where, ident in identities:
        for name, line in identity_offences(ident, args.policy):
            bad += 1
            print("%s: %s: %s" % (where, name, show(line)))
    for where, text in messages:
        for name, line in offences(text, args.policy):
            bad += 1
            print("%s: %s: %s" % (where, name, show(line)))
    if bad:
        print("check-trailers: %d offending line(s) (policy %s)" % (bad, args.policy))
        return 1
    print("check-trailers: %d message(s) clean (policy %s)" % (len(messages), args.policy))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
