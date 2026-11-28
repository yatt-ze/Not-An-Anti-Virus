#!/bin/sh
# Installs a released navctl and writes the install receipt (§13, #250).
#
#   curl -fsSL https://raw.githubusercontent.com/yatt-ze/Not-An-Anti-Virus/main/install.sh | sh
#
# Environment:
#   NAV_VERSION        install X.Y.Z (no leading "v") instead of the latest release
#   NAV_INSTALL_DIR    install directory (default: $HOME/.local/bin)
#   NAV_FORCE=1        overwrite a navctl that this script did not install
#   NO_COLOR           disable colour
#   NAV_DOWNLOAD_BASE  tests only: replaces the release download URL (https or
#                      file); requires NAV_VERSION
#
# Variables go on the sh side of the pipe: curl -fsSL … | NAV_VERSION=1.2.3 sh
#
# All logic lives in functions and main runs on the last line, so a truncated
# download executes nothing.

set -eu

REPO=yatt-ze/Not-An-Anti-Virus
SIGNER="https://github.com/$REPO/.github/workflows/release.yml@refs/heads/main"
SCRIPT_URL="https://raw.githubusercontent.com/$REPO/main/install.sh"
REPORT_URL="https://github.com/$REPO/security/advisories/new"
MIN_GH="2.102.0"

WORK=
TMP_BIN=
TMP_RECEIPT=
PREV_VERSION=
EXIST_NOTE=

# Symbols and colour only on a terminal; plain ASCII otherwise.
setup_style() {
    TICK=- DOT=- ARROW='->'
    B= DIM= CYN= Z= GRN= YEL= ERR= ECY= ERZ=
    if [ -t 1 ]; then
        TICK='✓' DOT='·' ARROW='→'
        if [ -z "${NO_COLOR:-}" ]; then
            esc=$(printf '\033')
            B="$esc[1m" DIM="$esc[2m" CYN="$esc[36m" Z="$esc[0m" GRN="$esc[32m" YEL="$esc[33m"
        fi
    fi
    if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
        esc=$(printf '\033')
        ERR="$esc[1m$esc[31m" ECY="$esc[36m" ERZ="$esc[0m"
    fi
}

# die MESSAGE [HINT]: one error line, then what to do next.
die() {
    printf '%serror:%s %s\n' "$ERR" "$ERZ" "$1" >&2
    [ -z "${2:-}" ] || printf '%s\n' "$2" >&2
    exit 1
}

# bad_download MESSAGE [ADVICE]: the release failed a check; says where to report it.
bad_download() {
    _advice="Don't use this download; please report it at:"
    [ -z "${2:-}" ] || _advice=$2
    die "$1" "Nothing was changed. $_advice
  $ECY$REPORT_URL$ERZ"
}

step() {
    printf '  %s%s%s %s\n' "$GRN" "$TICK" "$Z" "$1"
}

note() {
    printf '  %s%s%s %s\n' "$YEL" "$DOT" "$Z" "$1"
}

# Prints $1 with a leading home directory shown as ~.
pretty() {
    case $1 in
        "$HOME"/*) printf '%s/%s' '~' "${1#"$HOME"/}" ;;
        "$HOME_CANON"/*) printf '%s/%s' '~' "${1#"$HOME_CANON"/}" ;;
        *) printf '%s' "$1" ;;
    esac
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
        *'"'* | *\\*) die "$1 contains a quote or backslash" "Choose a path without quotes or backslashes." ;;
    esac
    _bad=$(printf '%s' "$2" | LC_ALL=C tr -d '[:print:]' | wc -c)
    [ "$_bad" -eq 0 ] || die "$1 contains a control or non-ASCII character" "Choose a path of plain ASCII characters."
}

check_platform() {
    _os=$(uname -s)
    [ "$_os" = Darwin ] || die "navctl is macOS-only (detected $_os)" "Build from source instead; see the README."
    [ "$(id -u)" -ne 0 ] || die "this script must not run as root" "Rerun it as your normal user; it never needs sudo."
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
        *) die "unsupported architecture ($(uname -m))" "navctl ships for arm64 and x86_64 Macs. Build from source instead." ;;
    esac
}

resolve_version() {
    if [ -n "${NAV_VERSION:-}" ]; then
        valid_version "$NAV_VERSION" ||
            die "NAV_VERSION must look like 1.2.3" "Use digits only, with no leading 'v'."
        echo "$NAV_VERSION"
        return
    fi
    _url=$(curl --proto '=https' --tlsv1.2 -fsSLI -o /dev/null -w '%{url_effective}' \
        "https://github.com/$REPO/releases/latest" 2>/dev/null) ||
        die "could not look up the latest release" "Check your connection and try again."
    _tag=${_url##*/}
    valid_version "${_tag#v}" ||
        die "unexpected latest-release URL" "Pin a version instead:
  ${ECY}curl -fsSL $SCRIPT_URL | NAV_VERSION=X.Y.Z sh$ERZ"
    echo "${_tag#v}"
}

fetch() {
    curl --proto "$PROTO" --tlsv1.2 -fsSL -o "$2" "$BASE/$1" 2>/dev/null ||
        die "could not download $1" "Nothing was changed. Check your connection and try again."
}

# The SHA256SUMS line for the asset must appear once and match the archive.
verify_checksum() {
    _count=$(awk -v a="$1" 'NF == 2 && $2 == a' "$WORK/SHA256SUMS" | wc -l)
    [ "$_count" -eq 1 ] ||
        bad_download "SHA256SUMS must list $1 exactly once"
    _want=$(awk -v a="$1" 'NF == 2 && $2 == a { print $1 }' "$WORK/SHA256SUMS")
    _got=$(shasum -a 256 "$WORK/$1" | awk '{ print $1 }')
    if [ -z "$_got" ] || [ "$_want" != "$_got" ]; then
        bad_download "checksum mismatch for $1" "Try again, and if it keeps happening, report it at:"
    fi
    step "Verified SHA-256 checksum"
}

verify_attestation() {
    _why=
    if ! command -v gh >/dev/null 2>&1; then
        _why="install gh $MIN_GH+ to enable it"
    else
        _line=$(gh --version 2>/dev/null | sed -n 1p) || _line=
        _g= _v= _ghver= _rest=
        read -r _g _v _ghver _rest <<EOT || true
$_line
EOT
        if [ "$_g" != gh ] || [ "$_v" != version ] || ! valid_version "$_ghver"; then
            _why="needs a stable gh $MIN_GH+"
        elif ! version_ge "$_ghver" "$MIN_GH"; then
            _why="gh $_ghver is older than $MIN_GH"
        elif ! gh auth status >/dev/null 2>&1; then
            _why="run gh auth login to enable it"
        fi
    fi
    if [ -n "$_why" ]; then
        note "Skipped build attestation check ($_why)"
        return
    fi
    gh attestation verify "$WORK/$1" --repo "$REPO" --cert-identity "$SIGNER" >/dev/null 2>&1 ||
        bad_download "build attestation verification failed for $1"
    step "Verified build attestation"
}

# Unpacks navctl into $WORK/stage and checks that it reports version $1.
extract_and_check() {
    [ "$(tar -tzf "$WORK/$2" 2>/dev/null)" = navctl ] ||
        bad_download "unexpected contents in $2"
    mkdir "$WORK/stage"
    tar -xzf "$WORK/$2" -C "$WORK/stage" navctl 2>/dev/null ||
        die "could not extract $2" "Nothing was changed."
    if [ ! -f "$WORK/stage/navctl" ] || [ -L "$WORK/stage/navctl" ]; then
        bad_download "navctl in $2 is not a regular file"
    fi
    chmod 755 "$WORK/stage/navctl"
    _got=$("$WORK/stage/navctl" --version 2>/dev/null) ||
        die "the downloaded navctl does not run" "Nothing was changed."
    [ "$_got" = "navctl $1" ] ||
        bad_download "downloaded navctl reports '$_got', expected 'navctl $1'"
}

# Refuses to replace a navctl this script did not install, unless NAV_FORCE=1.
# Sets PREV_VERSION (managed installs) and EXIST_NOTE.
check_existing() {
    { [ -e "$1" ] || [ -L "$1" ]; } || return 0
    [ ! -d "$1" ] || die "$1 is a directory" "Remove it or choose another NAV_INSTALL_DIR."
    if [ -f "$RECEIPT" ] && grep -Fxq "  \"binary_path\": \"$1\"," "$RECEIPT"; then
        PREV_VERSION=$(sed -n 's/^  "version": "\(.*\)",$/\1/p' "$RECEIPT")
        _old=$(sed -n 's/^  "binary_sha256": "\(.*\)"$/\1/p' "$RECEIPT")
        _now=$(shasum -a 256 "$1" 2>/dev/null | awk '{ print $1 }') || _now=
        if [ -n "$_now" ] && [ "$_now" != "$_old" ]; then
            EXIST_NOTE="$(pretty "$1") was modified since it was installed; replacing it"
        fi
    elif [ "${NAV_FORCE:-}" = 1 ]; then
        EXIST_NOTE="Replacing a navctl this script didn't install (NAV_FORCE=1)"
    else
        die "$(pretty "$1") already exists and wasn't installed by this script" "Remove it, or replace it with:
  ${ECY}curl -fsSL $SCRIPT_URL | NAV_FORCE=1 sh$ERZ"
    fi
}

# Copies into the target directory, then renames over any existing navctl.
place_binary() {
    TMP_BIN=$(mktemp "$1/.navctl.XXXXXX") ||
        die "cannot write to $1" "Check the directory's permissions, or choose another NAV_INSTALL_DIR."
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
    TMP_RECEIPT=$(umask 077 && mktemp "$_rdir/.receipt.XXXXXX") ||
        die "navctl was installed but the receipt could not be written" "Check that $_rdir is writable, then rerun this script."
    # Same layout as serde_json::to_string_pretty, so navctl rewrites match.
    printf '{\n  "schema": 1,\n  "version": "%s",\n  "target": "%s",\n  "binary_path": "%s",\n  "binary_sha256": "%s"\n}\n' \
        "$1" "$2" "$3" "$4" >"$TMP_RECEIPT"
    mv -f "$TMP_RECEIPT" "$RECEIPT"
    TMP_RECEIPT=
}

# Prints how to put $1 (the directory as the user gave it) on PATH.
path_hint() {
    _default=
    if [ -z "${NAV_INSTALL_DIR:-}" ] || [ "$1" = "$HOME/.local/bin" ]; then
        _default=1
    fi
    if [ -n "$_default" ]; then
        # Literal $HOME, for the user's startup file.
        # shellcheck disable=SC2016
        _val='$HOME/.local/bin'
    else
        _val=$(printf '%s' "$1" | sed 's/[$`]/\\&/g')
    fi
    _line="export PATH=\"$_val:\$PATH\""
    _then="Then open a new terminal."
    case $(basename "${SHELL:-}") in
        zsh) _how="Add this line to ~/.zshrc:" ;;
        bash) _how="Add this line to ~/.bash_profile:" ;;
        fish)
            _how="To add it, run:"
            _line="fish_add_path \"$_val\""
            _then=
            ;;
        *) _how="Add this line to your shell's startup file:" ;;
    esac
    printf "%s isn't on your PATH yet. %s\n  %s%s%s\n" "$(pretty "$1")" "$_how" "$CYN" "$_line" "$Z"
    [ -z "$_then" ] || printf '%s\n' "$_then"
    printf '\n'
}

# Warns when another navctl earlier on PATH would run instead of the one in $1.
shadow_hint() {
    _first=$(command -v navctl 2>/dev/null) || return 0
    _fdir=$(cd "$(dirname "$_first")" 2>/dev/null && pwd -P) || return 0
    [ "$_fdir" != "$1" ] || return 0
    case $_fdir in
        */.cargo/bin | "${CARGO_HOME:-$HOME/.cargo}/bin") _fix="Remove it with ${CYN}cargo uninstall navctl${Z}, or" ;;
        *) _fix="Remove it, or" ;;
    esac
    printf '%s!%s %s comes first on your PATH, so it runs instead.\n' "$YEL" "$Z" "$(pretty "$_fdir/navctl")"
    printf '  %s put %s earlier in your PATH.\n\n' "$_fix" "$(pretty "$1")"
}

main() {
    setup_style
    check_platform
    HOME=${HOME:-}
    [ -n "$HOME" ] || die "HOME is not set" "Set HOME to your home directory and rerun."
    check_path_chars HOME "$HOME"
    HOME_CANON=$(cd "$HOME" 2>/dev/null && pwd -P) || HOME_CANON=$HOME
    RECEIPT=$HOME/.local/share/nav/install-receipt.json

    if [ -n "${NAV_DOWNLOAD_BASE:-}" ] && [ -z "${NAV_VERSION:-}" ]; then
        die "NAV_DOWNLOAD_BASE requires NAV_VERSION" "Set NAV_VERSION as well."
    fi
    target=$(detect_target)
    dir=${NAV_INSTALL_DIR:-$HOME/.local/bin}
    check_path_chars NAV_INSTALL_DIR "$dir"
    # Refuse an unmanaged navctl before any network traffic.
    if [ -d "$dir" ]; then
        canon=$(cd "$dir" && pwd -P) || die "cannot enter $dir" "Check its permissions."
        check_path_chars "install path" "$canon"
        check_existing "$canon/navctl"
    fi
    version=$(resolve_version)

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
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/nav-install.XXXXXX") ||
        die "cannot create a temp directory" "Check that TMPDIR is writable."

    case $target in
        aarch64-*) chip="Apple silicon" ;;
        *) chip="Intel" ;;
    esac
    printf '%sInstalling navctl %s for %s%s %s(%s)%s\n' "$B" "$version" "$chip" "$Z" "$DIM" "$target" "$Z"
    asset=navctl-$version-$target.tar.gz
    fetch "$asset" "$WORK/$asset"
    fetch SHA256SUMS "$WORK/SHA256SUMS"
    _size=$(wc -c <"$WORK/$asset" | awk '{ printf "%.1f MB", $1 / 1000000 }')
    step "Downloaded ${DIM}($_size)${Z}"
    verify_checksum "$asset"
    verify_attestation "$asset"
    extract_and_check "$version" "$asset"
    [ -z "$EXIST_NOTE" ] || note "$EXIST_NOTE"

    mkdir -p "$dir" || die "cannot create $dir" "Choose another NAV_INSTALL_DIR."
    canon=$(cd "$dir" && pwd -P) || die "cannot enter $dir" "Check its permissions."
    check_path_chars "install path" "$canon"
    dest=$canon/navctl
    place_binary "$canon" "$dest"
    sha=$(shasum -a 256 "$dest" | awk '{ print $1 }')
    write_receipt "$version" "$target" "$dest" "$sha"

    if [ -z "$PREV_VERSION" ]; then
        result="Installed navctl $version"
    elif [ "$PREV_VERSION" = "$version" ]; then
        result="Reinstalled navctl $version"
    elif valid_version "$PREV_VERSION" && version_ge "$PREV_VERSION" "$version"; then
        result="Downgraded navctl $PREV_VERSION $ARROW $version"
    else
        result="Updated navctl $PREV_VERSION $ARROW $version"
    fi
    printf '%s%s%s in %s\n\n' "$B" "$result" "$Z" "$(pretty "$canon")"
    case ":${PATH:-}:" in
        *":$dir:"* | *":$canon:"*) shadow_hint "$canon" ;;
        *) path_hint "$dir" ;;
    esac
    printf 'Get started: %snavctl scan <file or .app>%s  (%snavctl --help%s for more)\n' "$CYN" "$Z" "$CYN" "$Z"
}

main "$@"
