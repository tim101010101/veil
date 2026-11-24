#!/bin/sh
# Bootstrap installer. The user trusts this script and its HTTPS source; subsequent
# managed Linux upgrades verify a release signature with the client's pinned public key.
set -eu

repository=https://github.com/tim101010101/veil
api=https://api.github.com/repos/tim101010101/veil
version=${VEIL_VERSION:-}
dir=${VEIL_INSTALL_DIR:-$HOME/.local/bin}
adopt=false
work=
lock=
next=
prepared=
cleanup() {
    [ -z "$next" ] || rm -f "$next"
    if [ -n "$prepared" ]; then
        if [ -L "$dir/veil" ] && [ "$(readlink "$dir/veil")" = "$prepared/veil" ]; then
            : # Activation already committed; retain the selected version after interruption.
        else
            rm -rf "$prepared"
        fi
    fi
    [ -z "$lock" ] || rm -f "$lock"
    [ -z "$work" ] || rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
while [ $# -gt 0 ]; do
    case "$1" in
        --version) [ $# -ge 2 ] || die '--version needs a value'; version=${2#v}; shift 2 ;;
        --dir) [ $# -ge 2 ] || die '--dir needs a directory'; dir=$2; shift 2 ;;
        --adopt) adopt=true; shift ;;
        -h|--help)
            printf '%s\n' 'Usage: install.sh [--version X.Y.Z] [--dir DIRECTORY] [--adopt]' \
                'Linux: managed version directory with an atomic launcher symlink.' \
                '--adopt explicitly migrates a direct standalone binary, retaining a copy.' \
                'Use the package manager for managed packages; macOS builds from source.'
            exit 0 ;;
        *) die 'unknown option; use --help' ;;
    esac
done
fetch() { curl -fsSL --proto '=https' --proto-redir '=https' --max-time 60 --retry 3 "$1"; }
if [ -z "$version" ]; then
    tag=$(fetch "$api/releases/latest" | tr ',' '\n' | sed -n 's/^.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*$/\1/p' | head -n 1)
    [ -n "$tag" ] || die 'cannot find a release; pass --version'
    version=${tag#v}
fi
case "$version" in ''|*[!0-9.]*|.*|*..*|*.) die 'installer requires a stable X.Y.Z version' ;; esac
[ "$(printf '%s' "$version" | tr -cd '.' | wc -c | tr -d ' ')" = 2 ] || die 'installer requires X.Y.Z'
mkdir -p "$dir"
dir=$(cd "$dir" && pwd -P)
case "$dir" in /bin|/sbin|/usr/bin|/usr/sbin|/nix/store|/nix/store/*) die 'use the system package manager for this directory' ;; esac
work=$(mktemp -d)

case "$(uname -s)" in
    Linux)
        case "$(uname -m)" in
            x86_64|amd64) arch=x86_64 ;;
            aarch64|arm64) arch=aarch64 ;;
            *) die 'no release binary for this architecture' ;;
        esac
        [ ! -L "$dir/.veil" ] || die 'refusing a symlinked management directory'
        mkdir -p "$dir/.veil"
        (set -C; printf 'pid=%s\n' "$$" > "$dir/.veil/upgrade.lock") 2>/dev/null \
            || die 'another installer/update may be active; inspect .veil/upgrade.lock before removing it'
        lock="$dir/.veil/upgrade.lock"
        legacy=false
        if [ -L "$dir/veil" ]; then
            installed=$(readlink -f "$dir/veil") || die 'cannot resolve existing launcher'
            case "$installed" in "$dir/.veil/"*/veil)
                # `*` also matches `/`: require exactly .veil/<version>/veil.
                [ "$(dirname "$(dirname "$installed")")" = "$dir/.veil" ] \
                    || die 'existing launcher points outside a managed version directory'
                receipt="$(dirname "$installed")/install.toml"
                grep -q '^source = "veil-installer-v1"$' "$receipt" \
                    || die 'existing launcher has no installer receipt'
                recorded=$(sed -n 's/^sha256 = "\([a-f0-9]*\)"$/\1/p' "$receipt")
                [ "$(sha256sum "$installed" | awk '{print $1}')" = "$recorded" ] \
                    || die 'installed binary changed outside this installer; refusing to overwrite it' ;;
                *) die 'existing symlink is not owned by this installer; use its original installation method' ;;
            esac
        elif [ -e "$dir/veil" ]; then
            [ -f "$dir/veil" ] && [ "$adopt" = true ] || die 'existing direct binary: use its package manager, or explicitly pass --adopt for a standalone install'
            legacy=true
        fi
        archive="veil-$version-linux-$arch.tar.gz"
        fetch "$repository/releases/download/v$version/$archive" > "$work/$archive" || die 'cannot download the release archive'
        fetch "$repository/releases/download/v$version/SHA256SUMS" > "$work/SHA256SUMS" || die 'cannot download release checksums'
        expected=$(awk -v file="$archive" '$2 == file || $2 == "*" file { print $1 }' "$work/SHA256SUMS")
        [ -n "$expected" ] || die 'archive has no checksum entry'
        actual=$(sha256sum "$work/$archive" | awk '{print $1}')
        [ "$actual" = "$expected" ] || die 'checksum mismatch; previous installation was not changed'
        [ "$(tar -tzf "$work/$archive")" = veil ] || die 'unexpected archive members'
        tar -xOzf "$work/$archive" veil > "$work/veil" || die 'cannot read the release binary'
        [ -s "$work/veil" ] || die 'empty release binary'
        prepared=$(mktemp -d "$dir/.veil/$version-XXXXXXXX")
        install -m 0755 "$work/veil" "$prepared/veil"
        digest=$(sha256sum "$prepared/veil" | awk '{print $1}')
        printf 'schema = 1\nsource = "veil-installer-v1"\nversion = "%s"\ntarget = "linux-%s"\nsha256 = "%s"\n' \
            "$version" "$arch" "$digest" > "$prepared/install.toml"
        chmod 0755 "$prepared"
        chmod 0644 "$prepared/install.toml"
        if [ "$legacy" = true ]; then
            previous=$(mktemp -d "$dir/.veil/legacy-XXXXXXXX")
            cp -p "$dir/veil" "$previous/veil"
            printf 'Previous standalone binary retained at %s/veil\n' "$previous" >&2
        fi
        next="$dir/.veil-launch-$(basename "$prepared")"
        ln -s "$prepared/veil" "$next"
        mv -Tf "$next" "$dir/veil"
        next=
        prepared=
        ;;
    Darwin)
        command -v cargo >/dev/null 2>&1 || die 'macOS needs Rust for a native source build'
        [ ! -L "$dir/veil" ] || die 'use the original installation method for this symlink'
        if [ -e "$dir/veil" ] && [ "$adopt" != true ]; then
            die 'replacing an existing native build requires --adopt; package-manager installs must use their manager'
        fi
        source=$repository.git
        printf 'Building native macOS veil v%s; CLI self-update is not supported for this installation.\n' "$version" >&2
        CARGO_NET_GIT_FETCH_WITH_CLI=true cargo install --quiet --locked --git "$source" --tag "v$version" --root "$work/root" veil-cli
        next=$(mktemp "$dir/.veil-native-XXXXXXXX")
        install -m 0755 "$work/root/bin/veil" "$next"
        if [ -f "$dir/veil" ]; then
            previous=$(mktemp "$dir/veil.previous-XXXXXXXX")
            cp -p "$dir/veil" "$previous"
            printf 'Previous native build retained at %s\n' "$previous" >&2
        fi
        mv -f "$next" "$dir/veil"
        next=
        ;;
    *) die 'unsupported operating system' ;;
esac
printf 'Installed veil %s at %s/veil\n' "$version" "$dir"
case ":$PATH:" in *":$dir:"*) ;; *) printf 'Add %s to PATH to run veil. Shell configuration was not changed.\n' "$dir" >&2 ;; esac
