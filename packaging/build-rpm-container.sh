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

selinux_enforcing() {
    if command -v getenforce >/dev/null 2>&1; then
        [ "$(getenforce 2>/dev/null || true)" = "Enforcing" ]
        return
    fi

    [ -r /sys/fs/selinux/enforce ] && [ "$(cat /sys/fs/selinux/enforce)" = "1" ]
}

container_engine=$(select_container_engine)
mount_spec="$repo_root:/src"

if selinux_enforcing; then
    mount_spec="$mount_spec:Z"
fi

container_image=${RPM_CONTAINER_IMAGE:-fedora:latest}

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
