#!/bin/sh

die() {
    printf 'aws-kms-sign-csr installer: %s\n' "$*" >&2
    exit 1
}

usage() {
    printf '%s\n' \
        'Usage: sh install.sh [--version TAG] [--bin-dir DIR]' \
        'Install the latest stable aws-kms-sign-csr release by default.' \
        'The default installation directory is ~/.local/bin.'
}

fetch() {
    curl -q --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' "$@"
}

cleanup() {
    if [ -n "$staged_binary" ]; then
        rm -f -- "$staged_binary"
    fi
    if [ -n "$work_dir" ]; then
        rm -rf -- "$work_dir"
    fi
}

main() {
    set -eu
    release_url=https://github.com/algonc/aws-kms-sign-csr/releases
    version=
    bin_dir=

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version|--bin-dir)
                case "${2-}" in
                    ''|--*) die "$1 requires a value" ;;
                esac
                case "$1" in
                    --version) version=$2 ;;
                    --bin-dir) bin_dir=$2 ;;
                esac
                shift 2
                ;;
            -h|--help) usage; return ;;
            *) die "unknown argument: $1 (see --help)" ;;
        esac
    done

    platform=$(uname -s)
    case "$platform" in
        Linux) os=linux ;;
        Darwin) os=darwin ;;
        *) die "unsupported operating system: $platform" ;;
    esac

    machine=$(uname -m)
    case "$machine" in
        x86_64|amd64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) die "unsupported architecture: $machine" ;;
    esac

    if [ -z "$bin_dir" ]; then
        [ -n "${HOME:-}" ] || die 'HOME is unset. Specify --bin-dir.'
        bin_dir=$HOME/.local/bin
    fi
    case "$bin_dir" in
        /*) ;;
        *) bin_dir=$PWD/$bin_dir ;;
    esac

    command -v curl >/dev/null 2>&1 || die 'curl is required'
    if command -v sha256sum >/dev/null 2>&1; then
        checksum() { sha256sum; }
    elif command -v shasum >/dev/null 2>&1; then
        checksum() { shasum -a 256; }
    else
        die 'sha256sum or shasum is required'
    fi

    if [ -z "$version" ]; then
        latest_url=$(fetch -o /dev/null -w '%{url_effective}' "$release_url/latest") ||
            die 'could not resolve the latest release'
        case "$latest_url" in
            "$release_url/tag/"*) version=${latest_url#"$release_url/tag/"} ;;
            *) die 'GitHub did not return a release tag' ;;
        esac
    fi
    case "$version" in
        *[!0-9A-Za-z.-]*) die "invalid release tag: $version" ;;
    esac
    printf '%s\n' "$version" |
        LC_ALL=C grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$' ||
        die "invalid release tag: $version"

    work_dir=
    staged_binary=
    trap cleanup 0
    trap 'exit 1' HUP INT TERM
    work_dir=$(mktemp -d "${TMPDIR:-/tmp}/aws-kms-sign-csr.XXXXXXXX") ||
        die 'could not create a temporary directory'

    asset=aws-kms-sign-csr_${version}_${os}_${arch}.tar.gz
    download_url=$release_url/download/$version
    fetch -o "$work_dir/checksums.txt" "$download_url/checksums.txt" ||
        die "could not download checksums for $version"
    expected=$(LC_ALL=C awk -v asset="$asset" '
        $2 == asset {
            matches++
            digest = $1
        }
        END {
            if (matches != 1 || length(digest) != 64 || digest ~ /[^0-9a-f]/) exit 1
            print digest
        }
    ' "$work_dir/checksums.txt") || die "missing or invalid checksum for $asset"

    fetch -o "$work_dir/$asset" "$download_url/$asset" ||
        die "could not download $asset"
    actual=$(checksum < "$work_dir/$asset") || die "could not hash $asset"
    [ "${actual%% *}" = "$expected" ] || die "checksum mismatch for $asset"

    tar -xOzf "$work_dir/$asset" aws-kms-sign-csr > "$work_dir/aws-kms-sign-csr" ||
        die "could not extract aws-kms-sign-csr from $asset"
    [ -s "$work_dir/aws-kms-sign-csr" ] || die "the extracted executable is empty"

    mkdir -p "$bin_dir" || die "could not create $bin_dir"
    staged_binary=$(mktemp "$bin_dir/.aws-kms-sign-csr.XXXXXXXX") ||
        die "could not create a temporary file in $bin_dir"
    install -m 755 "$work_dir/aws-kms-sign-csr" "$staged_binary" ||
        die "could not stage the executable in $bin_dir"
    destination=$bin_dir/aws-kms-sign-csr
    [ ! -d "$destination" ] || die "installation path points to a directory: $destination"
    mv -f "$staged_binary" "$destination" || die "could not replace $destination"
    staged_binary=

    printf 'Installed aws-kms-sign-csr %s to %s\n' "$version" "$destination"
    case ":${PATH:-}:" in
        *":$bin_dir:"*) ;;
        *) printf 'Add %s to your PATH to run aws-kms-sign-csr by name.\n' "$bin_dir" ;;
    esac
}

main "$@"
