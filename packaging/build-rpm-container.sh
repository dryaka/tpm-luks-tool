#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
container_engine=${CONTAINER_ENGINE:-podman}
container_image=${RPM_CONTAINER_IMAGE:-fedora:latest}
engine_name=${container_engine##*/}

if ! command -v "$container_engine" >/dev/null 2>&1; then
    echo "Container engine not found: $container_engine" >&2
    echo "Install Podman or set CONTAINER_ENGINE to another compatible engine." >&2
    exit 1
fi

mount_spec="$repo_root:/src"
if [ "$engine_name" = "podman" ]; then
    mount_spec="$mount_spec:Z"
fi

exec "$container_engine" run --rm \
    -v "$mount_spec" \
    -w /src \
    "$container_image" \
    sh -eu -c '
        dnf -y install \
            git gzip rpm rpm-build pyproject-rpm-macros \
            python3-devel python3-pip python3-setuptools python3-wheel
        ./packaging/build-rpm.sh
    '
