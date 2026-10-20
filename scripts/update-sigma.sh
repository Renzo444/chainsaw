#!/usr/bin/env sh
# Refreshes the Sigma rules bundled into the Chainsaw binary from SigmaHQ.
#
# Usage: scripts/update-sigma.sh [git-ref]
set -eu

REF="${1:-master}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

git clone --quiet --depth 1 --branch "$REF" https://github.com/SigmaHQ/sigma "$TMP/sigma"

rm -rf "$ROOT/sigma"
mkdir -p "$ROOT/sigma/rules"
cp -R "$TMP/sigma/rules/windows" "$ROOT/sigma/rules/windows"
cp -R "$TMP/sigma/rules-emerging-threats" "$ROOT/sigma/rules-emerging-threats"
find "$ROOT/sigma" -type f ! -name '*.yml' -delete
cp "$TMP/sigma/LICENSE" "$ROOT/sigma/LICENSE"

COMMIT="$(git -C "$TMP/sigma" rev-parse HEAD)"
DATE="$(git -C "$TMP/sigma" log -1 --format=%cs)"
cat > "$ROOT/sigma/README.md" <<EOF
# Bundled Sigma rules

These rules are copied from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma).

- Commit: \`$COMMIT\`
- Date: $DATE

They are embedded into the Chainsaw binary so that \`chainsaw hunt\` works without any extra
downloads.

The rules are released under the
[Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License); the
author of each rule is credited in the rule itself.

Refresh them with \`scripts/update-sigma.sh\`.
EOF
echo "Bundled Sigma rules updated to $COMMIT"
