#!/usr/bin/env bash
set -euo pipefail

# Removes only Maatram's marked block from /etc/hosts and preserves other entries.
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

python3 - "$tmp" <<'PY'
from pathlib import Path
import sys

source = Path("/etc/hosts").read_text()
lines = source.splitlines()
out = []
i = 0
changed = False
while i < len(lines):
    if lines[i].strip() != "# MAATRAM-BEGIN":
        out.append(lines[i])
        i += 1
        continue
    changed = True
    end = next((j for j in range(i + 1, len(lines)) if lines[j].strip() == "# MAATRAM-END"), None)
    if end is None:
        # Match the app's conservative recovery behavior for a damaged block:
        # remove only the marker rather than deleting user entries after it.
        i += 1
    else:
        i = end + 1

if not changed:
    print("No Maatram hosts block found; nothing to restore.")
    sys.exit(3)

result = "\n".join(out)
if source.endswith("\n") and result:
    result += "\n"
Path(sys.argv[1]).write_text(result)
PY
