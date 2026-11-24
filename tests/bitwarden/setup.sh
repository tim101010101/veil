#!/bin/sh
# Installs the pinned clients the compatibility suite drives. Idempotent.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
. "$here/versions.env"
home=${COMPAT_HOME:-$HOME/.cache/veil-compat}
registry=${NPM_REGISTRY:-https://registry.npmjs.org}
mkdir -p "$home"
cd "$home"

if [ ! -x "$home/npm/bin/bw" ] || [ "$("$home/npm/bin/bw" --version)" != "$BW_VERSION" ]; then
    npm install --silent --prefix "$home/npm" --global --registry "$registry" "@bitwarden/cli@$BW_VERSION"
fi

if [ ! -d "$home/pw/node_modules/playwright" ]; then
    mkdir -p "$home/pw"
    (cd "$home/pw" && npm init -y >/dev/null && npm install --silent --registry "$registry" "playwright@$PLAYWRIGHT_VERSION")
fi
# The Playwright CI image ships the matching Chromium; install it only where it is missing.
if [ -z "${PLAYWRIGHT_BROWSERS_PATH:-}" ] || ! ls "$PLAYWRIGHT_BROWSERS_PATH" | grep -q '^chromium-'; then
    (cd "$home/pw" && npx playwright install chromium >/dev/null)
fi
# System libraries for Chromium; only possible as root (CI containers are).
if [ "$(id -u)" = 0 ]; then
    (cd "$home/pw" && npx playwright install-deps chromium >/dev/null)
fi

if [ ! -f "$home/ext-$EXTENSION_VERSION/manifest.json" ]; then
    curl -fsSL -o "$home/ext.zip" \
        "https://github.com/bitwarden/clients/releases/download/browser-v$EXTENSION_VERSION/dist-chrome-$EXTENSION_VERSION.zip"
    rm -rf "$home/ext-$EXTENSION_VERSION"
    mkdir -p "$home/ext-$EXTENSION_VERSION"
    python3 -m zipfile -e "$home/ext.zip" "$home/ext-$EXTENSION_VERSION"
fi

if ! command -v caddy >/dev/null 2>&1 && [ ! -x "$home/caddy" ]; then
    curl -fsSL -o "$home/caddy" "https://caddyserver.com/api/download?os=linux&arch=amd64"
    chmod +x "$home/caddy"
fi
echo "compat clients ready in $home: bw $BW_VERSION, extension $EXTENSION_VERSION"
