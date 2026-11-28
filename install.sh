#!/bin/sh
# Installs a released navctl and writes the install receipt (§13, #250).
#
#   curl -fsSL https://raw.githubusercontent.com/yatt-ze/Not-An-Anti-Virus/main/install.sh | sh
#
# Environment:
#   NAV_VERSION        install X.Y.Z (no leading "v") instead of the latest release
#   NAV_INSTALL_DIR    install directory (default: $HOME/.local/bin)
#   NAV_FORCE=1        overwrite a navctl that this script did not install
#   NAV_DOWNLOAD_BASE  tests only: replaces the release download URL (https or
#                      file); requires NAV_VERSION
#
# All logic lives in functions and main runs on the last line, so a truncated
# download executes nothing.

set -eu

REPO=yatt-ze/Not-An-Anti-Virus
SIGNER="https://github.com/$REPO/.github/workflows/release.yml@refs/heads/main"
MIN_GH="2.102.0"

WORK=
TMP_BIN=
TMP_RECEIPT=

die() {
    printf 'install.sh: %s\n' "$*" >&2
    exit 1
}

note() {
    printf '%s\n' "$*"
}

cleanup() {
    [ -z "$TMP_BIN" ] || rm -f "$TMP_BIN"
    [ -z "$TMP_RECEIPT" ] || rm -f "$TMP_RECEIPT"
    [ -z "$WORK" ] || rm -rf "$WORK"
}

# Exactly X.Y.Z, digits only.
valid_version() {
    case $1 in
        '' | *[!0-9.]* | .* | *. | *..*) return 1 ;;
    esac
    _ifs=$IFS
    IFS=.
    # shellcheck disable=SC2086
    set -- $1
    IFS=$_ifs
    [ $# -eq 3 ]
}

# True if the version $1 is at least $2 (both valid X.Y.Z).
version_ge() {
    _ifs=$IFS
    IFS=.
    # shellcheck disable=SC2086
    set -- $1 $2
    IFS=$_ifs
    [ "$1" -gt "$4" ] && return 0
    [ "$1" -lt "$4" ] && return 1
    [ "$2" -gt "$5" ] && return 0
    [ "$2" -lt "$5" ] && return 1
    [ "$3" -ge "$6" ]
}

# Rejects characters that would need escaping in the receipt's JSON.
check_path_chars() {
    case $2 in
        *'"'* | *\\*) die "$1 contains a quote or backslash: refusing" ;;
    esac
    _bad=$(printf '%s' "$2" | LC_ALL=C tr -d '[:print:]' | wc -c)
    [ "$_bad" -eq 0 ] || die "$1 contains a control or non-ASCII character: refusing"
}

check_platform() {
    [ "$(uname -s)" = Darwin ] || die "navctl is macOS-only"
    [ "$(id -u)" -ne 0 ] || die "do not run as root; the install never needs it"
}

detect_target() {
    case $(uname -m) in
        arm64) echo aarch64-apple-darwin ;;
        x86_64)
            if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
                echo aarch64-apple-darwin # Rosetta shell on an Apple silicon Mac
            else
                echo x86_64-apple-darwin
            fi
            ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac
}

resolve_version() {
    if [ -n "${NAV_VERSION:-}" ]; then
        valid_version "$NAV_VERSION" || die "NAV_VERSION must look like 1.2.3"
        echo "$NAV_VERSION"
        return
    fi
    _url=$(curl --proto '=https' --tlsv1.2 -fsSLI -o /dev/null -w '%{url_effective}' \
        "https://github.com/$REPO/releases/latest") ||
        die "could not look up the latest release"
    _tag=${_url##*/}
    valid_version "${_tag#v}" || die "unexpected latest-release URL: $_url"
    echo "${_tag#v}"
}

fetch() {
    curl --proto "$PROTO" --tlsv1.2 -fsSL -o "$2" "$BASE/$1" || die "download failed: $1"
}

# The SHA256SUMS line for the asset must appear once and match the archive.
verify_checksum() {
    _count=$(awk -v a="$1" 'NF == 2 && $2 == a' "$WORK/SHA256SUMS" | wc -l)
    [ "$_count" -eq 1 ] || die "SHA256SUMS must list $1 exactly once"
    _want=$(awk -v a="$1" 'NF == 2 && $2 == a { print $1 }' "$WORK/SHA256SUMS")
    _got=$(shasum -a 256 "$WORK/$1" | awk '{ print $1 }')
    [ -n "$_got" ] && [ "$_want" = "$_got" ] || die "checksum mismatch for $1"
}

verify_attestation() {
    _why=
    if ! command -v gh >/dev/null 2>&1; then
        _why="gh is not installed"
    else
        _line=$(gh --version 2>/dev/null | sed -n 1p) || _line=
        _g= _v= _ghver= _rest=
        read -r _g _v _ghver _rest <<EOT || true
$_line
EOT
        if [ "$_g" != gh ] || [ "$_v" != version ] || ! valid_version "$_ghver"; then
            _why="gh version is unusable (need a stable release >= $MIN_GH)"
        elif ! version_ge "$_ghver" "$MIN_GH"; then
            _why="gh $_ghver is older than $MIN_GH"
        elif ! gh auth status >/dev/null 2>&1; then
            _why="gh is not logged in"
        fi
    fi
    if [ -n "$_why" ]; then
        note "Checked the SHA-256 only (not the attestation): $_why."
        return
    fi
    gh attestation verify "$WORK/$1" --repo "$REPO" --cert-identity "$SIGNER" ||
        die "attestation verification failed for $1"
    note "Verified the SHA-256 and the build attestation."
}

# Unpacks navctl into $WORK/stage and checks that it reports version $1.
extract_and_check() {
    [ "$(tar -tzf "$WORK/$2")" = navctl ] || die "$2 must contain only navctl"
    mkdir "$WORK/stage"
    tar -xzf "$WORK/$2" -C "$WORK/stage" navctl || die "could not extract $2"
    [ -f "$WORK/stage/navctl" ] && [ ! -L "$WORK/stage/navctl" ] ||
        die "navctl in $2 is not a regular file"
    chmod 755 "$WORK/stage/navctl"
    _got=$("$WORK/stage/navctl" --version) || die "the downloaded navctl does not run"
    [ "$_got" = "navctl $1" ] || die "downloaded navctl reports '$_got', expected 'navctl $1'"
}

# Refuses to replace a navctl this script did not install, unless NAV_FORCE=1.
check_existing() {
    { [ -e "$1" ] || [ -L "$1" ]; } || return 0
    [ ! -d "$1" ] || die "$1 is a directory"
    if [ -f "$RECEIPT" ] && grep -Fxq "  \"binary_path\": \"$1\"," "$RECEIPT"; then
        _old=$(sed -n 's/^  "binary_sha256": "\(.*\)"$/\1/p' "$RECEIPT")
        _now=$(shasum -a 256 "$1" 2>/dev/null | awk '{ print $1 }') || _now=
        if [ -n "$_now" ] && [ "$_now" != "$_old" ]; then
            note "Note: $1 no longer matches its install receipt; replacing it."
        fi
    elif [ "${NAV_FORCE:-}" = 1 ]; then
        note "Note: replacing a navctl this script did not install (NAV_FORCE=1)."
    else
        die "$1 exists and was not installed by this script; set NAV_FORCE=1 to replace it"
    fi
}

# Copies into the target directory, then renames over any existing navctl.
place_binary() {
    TMP_BIN=$(mktemp "$1/.navctl.XXXXXX") || die "cannot write to $1"
    cp "$WORK/stage/navctl" "$TMP_BIN"
    chmod 755 "$TMP_BIN"
    mv -f "$TMP_BIN" "$2"
    TMP_BIN=
}

write_receipt() {
    _rdir=$(dirname "$RECEIPT")
    if [ ! -d "$_rdir" ]; then
        mkdir -p "$(dirname "$_rdir")"
        mkdir -m 700 "$_rdir"
    fi
    TMP_RECEIPT=$(umask 077 && mktemp "$_rdir/.receipt.XXXXXX") || die "cannot write the receipt"
    # Same layout as serde_json::to_string_pretty, so navctl rewrites match.
    printf '{\n  "schema": 1,\n  "version": "%s",\n  "target": "%s",\n  "binary_path": "%s",\n  "binary_sha256": "%s"\n}\n' \
        "$1" "$2" "$3" "$4" >"$TMP_RECEIPT"
    mv -f "$TMP_RECEIPT" "$RECEIPT"
    TMP_RECEIPT=
}

main() {
    check_platform
    HOME=${HOME:-}
    [ -n "$HOME" ] || die "HOME is not set"
    check_path_chars HOME "$HOME"
    RECEIPT=$HOME/.local/share/nav/install-receipt.json

    if [ -n "${NAV_DOWNLOAD_BASE:-}" ] && [ -z "${NAV_VERSION:-}" ]; then
        die "NAV_DOWNLOAD_BASE requires NAV_VERSION"
    fi
    target=$(detect_target)
    version=$(resolve_version)
    dir=${NAV_INSTALL_DIR:-$HOME/.local/bin}
    check_path_chars NAV_INSTALL_DIR "$dir"

    if [ -n "${NAV_DOWNLOAD_BASE:-}" ]; then
        BASE=$NAV_DOWNLOAD_BASE # tests only
        PROTO='=https,file'
    else
        BASE=https://github.com/$REPO/releases/download/v$version
        PROTO='=https'
    fi

    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/nav-install.XXXXXX") || die "cannot create a temp dir"

    asset=navctl-$version-$target.tar.gz
    note "Downloading navctl $version for $target..."
    fetch "$asset" "$WORK/$asset"
    fetch SHA256SUMS "$WORK/SHA256SUMS"
    verify_checksum "$asset"
    verify_attestation "$asset"
    extract_and_check "$version" "$asset"

    mkdir -p "$dir"
    canon=$(cd "$dir" && pwd -P) || die "cannot enter $dir"
    check_path_chars "install path" "$canon"
    dest=$canon/navctl
    check_existing "$dest"
    place_binary "$canon" "$dest"
    sha=$(shasum -a 256 "$dest" | awk '{ print $1 }')
    write_receipt "$version" "$target" "$dest" "$sha"

    note "Installed navctl $version to $dest"
    case ":${PATH:-}:" in
        *":$dir:"* | *":$canon:"*) ;;
        *)
            note "$dir is not on your PATH. Add it with:"
            note "  export PATH=\"$dir:\$PATH\""
            ;;
    esac
}

main "$@"
