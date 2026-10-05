#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
container_engine=${CONTAINER_ENGINE:-podman}
container_image=${DEB_CONTAINER_IMAGE:-debian:12}
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
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            build-essential ca-certificates debhelper dh-python dpkg-dev fakeroot git \
            pybuild-plugin-pyproject python3-all python3-setuptools python3-wheel
        ./packaging/build-deb.sh
    '
