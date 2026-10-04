#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' pyproject.toml | head -n 1)
deb_version=$(dpkg-parsechangelog -l packaging/debian/changelog -SVersion)
upstream_deb_version=${deb_version%%-*}

if [ -z "$version" ] || [ "$version" != "$upstream_deb_version" ]; then
    echo "DEB version mismatch: pyproject=$version changelog=$deb_version" >&2
    exit 1
fi

distdir=${DIST_DIR:-"$repo_root/dist/deb"}
buildroot=${DEB_BUILD_ROOT:-"$repo_root/.build/deb"}
source_parent="$buildroot/source"
source_dir="$source_parent/tpm-luks-tool-$version"

rm -rf "$distdir" "$buildroot"
mkdir -p "$distdir" "$source_dir"

if git -c safe.directory="$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -c safe.directory="$repo_root" archive --format=tar HEAD | tar -xf - -C "$source_dir"
else
    echo "DEB build requires a Git checkout so the source tree is reproducible." >&2
    exit 1
fi

cp -a "$source_dir/packaging/debian" "$source_dir/debian"

(
    cd "$source_dir"
    dpkg-buildpackage -us -uc -b
)

find "$source_parent" -maxdepth 1 -type f \
    \( -name 'tpm-luks-tool_*.deb' -o -name 'tpm-luks-tool_*.buildinfo' -o -name 'tpm-luks-tool_*.changes' \) \
    -exec cp -p {} "$distdir/" \;

echo "DEB artifacts:"
find "$distdir" -maxdepth 1 -type f -print
