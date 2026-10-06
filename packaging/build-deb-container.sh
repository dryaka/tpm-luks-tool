#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

select_container_engine() {
    if [ -n "${CONTAINER_ENGINE:-}" ]; then
        if command -v "$CONTAINER_ENGINE" >/dev/null 2>&1; then
            printf '%s\n' "$CONTAINER_ENGINE"
            return
        fi
        echo "Container engine not found: $CONTAINER_ENGINE" >&2
        exit 1
    fi

    if command -v podman >/dev/null 2>&1; then
        printf '%s\n' podman
        return
    fi

    if command -v docker >/dev/null 2>&1; then
        printf '%s\n' docker
        return
    fi

    echo "No compatible container engine found." >&2
    echo "Install Podman or Docker, or set CONTAINER_ENGINE explicitly." >&2
    exit 1
}

ensure_image() {
    image=$1
    if ! "$container_engine" image inspect "$image" >/dev/null 2>&1; then
        "$container_engine" pull "$image"
    fi
}

cleanup_container() {
    if [ -n "${container_id:-}" ]; then
        "$container_engine" rm -f "$container_id" >/dev/null 2>&1 || :
    fi
}

container_engine=$(select_container_engine)
container_id=""
trap cleanup_container 0

container_image=${DEB_CONTAINER_IMAGE:-debian:12}
ensure_image "$container_image"

container_id=$(
    "$container_engine" create "$container_image" \
        sh -c 'trap "exit 0" TERM INT; while :; do sleep 3600; done'
)
"$container_engine" start "$container_id" >/dev/null
"$container_engine" exec "$container_id" mkdir -p /src
"$container_engine" cp "$repo_root/." "$container_id:/src"

"$container_engine" exec -w /src "$container_id" sh -eu -c '
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential ca-certificates debhelper dh-python dpkg-dev fakeroot git \
        pybuild-plugin-pyproject python3-all python3-setuptools python3-wheel
    ./packaging/build-deb.sh
'

rm -rf "$repo_root/dist/deb"
mkdir -p "$repo_root/dist/deb"
"$container_engine" cp "$container_id:/src/dist/deb/." "$repo_root/dist/deb"

echo "Container-built DEB artifacts:"
find "$repo_root/dist/deb" -maxdepth 1 -type f -print
