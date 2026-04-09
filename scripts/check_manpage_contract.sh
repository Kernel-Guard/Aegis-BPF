#!/usr/bin/env bash
# Ensure every top-level subcommand that cli_dispatch.cpp routes to also has a
# matching "### <cmd>" section in docs/man/aegisbpf.1.md. Prevents silent
# man-page drift as we add/remove CLI verbs.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DISPATCH_FILE="${REPO_ROOT}/src/cli_dispatch.cpp"
MANPAGE_FILE="${REPO_ROOT}/docs/man/aegisbpf.1.md"

if [[ ! -f "${DISPATCH_FILE}" ]]; then
    echo "cli_dispatch.cpp not found at ${DISPATCH_FILE}" >&2
    exit 2
fi
if [[ ! -f "${MANPAGE_FILE}" ]]; then
    echo "man page source not found at ${MANPAGE_FILE}" >&2
    exit 2
fi

python3 - "${DISPATCH_FILE}" "${MANPAGE_FILE}" <<'PY'
import pathlib
import re
import sys

dispatch_path = pathlib.Path(sys.argv[1])
manpage_path = pathlib.Path(sys.argv[2])

dispatch = dispatch_path.read_text(encoding="utf-8")
manpage = manpage_path.read_text(encoding="utf-8")

# Extract subcommands from `if (cmd == "...")` lines in cli_dispatch.cpp.
# We intentionally skip aliases (--version, -V) that share a handler and
# skip any cmd that is self-documented by the SYNOPSIS line (handled by
# --help / the usage() dump). Everything else must have a man section.
cmd_pattern = re.compile(r'if \(cmd == "([^"]+)"\)')
aliases = {"--version", "-V"}
dispatched = []
for match in cmd_pattern.finditer(dispatch):
    name = match.group(1)
    if name in aliases:
        continue
    dispatched.append(name)

# Preserve insertion order but drop dupes.
seen = set()
commands = []
for name in dispatched:
    if name in seen:
        continue
    seen.add(name)
    commands.append(name)

# Extract "### <name>" headings from the man page.
man_pattern = re.compile(r"^### (\S+)", re.MULTILINE)
documented = {m.group(1) for m in man_pattern.finditer(manpage)}

missing = [cmd for cmd in commands if cmd not in documented]

# Optional: flag documented sections that no longer have a dispatcher.
stray = sorted(documented - set(commands) - {"options"})

exit_code = 0
if missing:
    print("error: the following CLI subcommands have no ### section in", manpage_path)
    for cmd in missing:
        print(f"  - {cmd}")
    exit_code = 1

if stray:
    print("warning: man page documents commands that are not in cli_dispatch.cpp:")
    for cmd in stray:
        print(f"  - {cmd}")

if exit_code == 0 and not stray:
    print(f"ok: {len(commands)} CLI subcommands, all documented")

sys.exit(exit_code)
PY
