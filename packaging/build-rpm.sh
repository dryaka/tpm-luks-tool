#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

rpm_host_profile() {
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID:-}:${VERSION_ID:-}" in
            rocky:9*|rhel:9*|almalinux:9*|centos:9*)
                echo "el9"
                return
                ;;
            fedora:*)
                echo "fedora"
                return
                ;;
        esac
    fi

    echo "generic"
}

required_packages_for_host() {
    case "$1" in
        el9)
            echo "git gzip rpm rpm-build pyproject-rpm-macros python3.11-devel python3.11-pip python3.11-setuptools python3.11-wheel python3.11-rpm-macros"
            ;;
        *)
            echo "git gzip rpm rpm-build pyproject-rpm-macros python3-devel python3-pip python3-setuptools python3-wheel"
            ;;
    esac
}

fail_missing_packages() {
    missing_packages=$1
    host_profile=$2

    echo "Missing RPM build dependencies:" >&2
    for package in $missing_packages; do
        echo "  $package" >&2
    done
    echo >&2
    echo "These packages are needed to build tpm-luks-tool; they are not runtime dependencies of the resulting RPM." >&2
    echo >&2

    if command -v dnf >/dev/null 2>&1; then
        if [ "$host_profile" = "el9" ]; then
            echo "On Rocky/RHEL-compatible 9, CRB may need to be enabled first:" >&2
            echo "  sudo dnf install dnf-plugins-core" >&2
            echo "  sudo dnf config-manager --set-enabled crb" >&2
            echo >&2
        fi
        echo "Install the missing build dependencies with:" >&2
        echo "  sudo dnf install $missing_packages" >&2
    else
        echo "Install the listed packages with your system package manager." >&2
    fi
    exit 1
}

preflight_build_dependencies() {
    host_profile=$(rpm_host_profile)
    required_packages=$(required_packages_for_host "$host_profile")

    if ! command -v rpm >/dev/null 2>&1; then
        fail_missing_packages "$required_packages" "$host_profile"
    fi

    missing_packages=""

    for package in $required_packages; do
        if ! rpm -q --whatprovides "$package" >/dev/null 2>&1; then
            if [ -z "$missing_packages" ]; then
                missing_packages=$package
            else
                missing_packages="$missing_packages $package"
            fi
        fi
    done

    if [ -n "$missing_packages" ]; then
        fail_missing_packages "$missing_packages" "$host_profile"
    fi

    missing_commands=""
    for command_name in git gzip rpm rpmbuild; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            if [ -z "$missing_commands" ]; then
                missing_commands=$command_name
            else
                missing_commands="$missing_commands $command_name"
            fi
        fi
    done

    if [ -n "$missing_commands" ]; then
        echo "RPM build packages are installed, but required commands are not available in PATH:" >&2
        for command_name in $missing_commands; do
            echo "  $command_name" >&2
        done
        exit 1
    fi
}

preflight_build_dependencies

version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' pyproject.toml | head -n 1)
spec_version=$(sed -n 's/^Version:[[:space:]]*//p' packaging/rpm/tpm-luks-tool.spec | head -n 1)

if [ -z "$version" ] || [ "$version" != "$spec_version" ]; then
    echo "RPM version mismatch: pyproject=$version spec=$spec_version" >&2
    exit 1
fi

topdir=${RPM_TOPDIR:-"$repo_root/.build/rpm"}
distdir=${DIST_DIR:-"$repo_root/dist/rpm"}

rm -rf "$topdir" "$distdir"
mkdir -p "$topdir/BUILD" "$topdir/BUILDROOT" "$topdir/RPMS" "$topdir/SOURCES" "$topdir/SPECS" "$topdir/SRPMS" "$distdir"

source_archive="$topdir/SOURCES/tpm-luks-tool-$version.tar.gz"

if git -c safe.directory="$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -c safe.directory="$repo_root" archive --format=tar --prefix="tpm-luks-tool-$version/" HEAD | gzip -n > "$source_archive"
else
    echo "RPM build requires a Git checkout so the source archive is reproducible." >&2
    exit 1
fi

cp packaging/rpm/tpm-luks-tool.spec "$topdir/SPECS/"

rpmbuild -ba \
    --define "_topdir $topdir" \
    "$topdir/SPECS/tpm-luks-tool.spec"

find "$topdir/RPMS" "$topdir/SRPMS" -type f -name '*.rpm' -exec cp -p {} "$distdir/" \;

echo "RPM artifacts:"
find "$distdir" -maxdepth 1 -type f -name '*.rpm' -print
