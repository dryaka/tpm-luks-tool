#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

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
