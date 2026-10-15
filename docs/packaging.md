# Native RPM and DEB packaging

## Purpose

The project provides native packages so normal administration does not require
`sudo pip`, a virtual environment, or direct source-tree execution.

Both package formats install the same application and keep configuration,
runtime state, and audit history separate.

## Package identity

Binary package name:

```text
tpm-luks-tool
```

Installed command:

```text
/usr/bin/tpm-luks
```

The project is an administrator-facing application rather than a reusable
Python library package, so the native package itself is not named
`python3-tpm-luks-tool`.

## Installed filesystem layout

Conceptually:

```text
/usr/bin/tpm-luks
/usr/lib/python3*/.../tpm_luks/          # distro-specific Python module path
/etc/tpm-luks.toml                       # package-managed administrator policy
/usr/share/doc/tpm-luks-tool/            # README and architecture/packaging docs
/var/lib/tpm-luks/                       # install-created runtime state; not package-owned
```

The packaged `/etc/tpm-luks.toml` is the safe example policy from
`examples/tpm-luks.toml`. Its UUIDs and backup path are placeholders and must
be replaced before mutating commands are used.

The package never installs secrets, passphrases, private keys, production TPM
metadata, or LUKS header backups.

Installation ships a `systemd-tmpfiles` definition that creates
`/var/lib/tpm-luks` and `/var/lib/tpm-luks/history` as `root:root` mode
`0700`. The directories themselves are not package payload files, so package
removal does not remove runtime state or audit history.

## Runtime dependencies

The application requires:

- Python 3.11 or newer,
- `cryptsetup`,
- `systemd`, including `systemd-analyze` and `systemd-cryptenroll`.

There are no third-party Python runtime dependencies.

## RPM

### Target systems

The RPM definition is intended for:

- current Fedora releases using the distribution default Python,
- Rocky Linux 9 using the parallel Python 3.11 stack.

On RHEL-compatible version 9 systems the spec sets
`python3_pkgversion=3.11`, so the installed application uses
`/usr/bin/python3.11` and the matching site-packages directory rather than the
default Python 3.9 stack.

### Build dependencies

Fedora:

```bash
sudo dnf install \
  git gzip rpm rpm-build pyproject-rpm-macros \
  python3-devel python3-pip python3-setuptools python3-wheel
```

Rocky Linux 9:

```bash
sudo dnf install dnf-plugins-core
sudo dnf config-manager --set-enabled crb
sudo dnf install \
  git gzip rpm rpm-build pyproject-rpm-macros \
  python3.11-devel python3.11-pip python3.11-setuptools \
  python3.11-wheel python3.11-rpm-macros
```

### Build

From a clean Git checkout:

```bash
sh packaging/build-rpm.sh
```

Before building, the helper checks the required RPM build toolchain and
distribution-specific build packages. On Fedora it checks the default Python
stack; on RHEL-compatible version 9 systems it checks the Python 3.11 stack.
If anything is missing, it exits before `rpmbuild` and prints the exact
`sudo dnf install ...` command required to satisfy the preflight.

The preflight never installs packages automatically. Build dependencies are
needed only to construct the RPM and are distinct from the runtime dependencies
declared by the resulting package.

After preflight, the helper creates a reproducible source archive from `HEAD`,
runs `rpmbuild -ba`, and writes binary/source RPMs under:

```text
dist/rpm/
```

The RPM spec is:

```text
packaging/rpm/tpm-luks-tool.spec
```

### Install

```bash
sudo dnf install ./dist/rpm/tpm-luks-tool-*.noarch.rpm
```

The policy file is marked `%config(noreplace)`, so upgrades do not overwrite an
administrator-modified `/etc/tpm-luks.toml`. On package erase, normal RPM
configuration-file preservation rules apply; runtime state/history are
unaffected because they are not package-owned.

## DEB

### Target systems

The DEB definition is intended for Debian 12 or newer and Ubuntu 24.04 LTS or
newer. It uses Debian's `pybuild` PEP 517 integration and the distribution
Python 3 interpreter.

### Build dependencies

```bash
sudo apt update
sudo apt install \
  build-essential debhelper dh-python dpkg-dev \
  pybuild-plugin-pyproject \
  python3-all python3-setuptools python3-wheel
```

### Repository layout

Debian metadata is kept under:

```text
packaging/debian/
```

The build helper creates a clean temporary source tree under `.build/deb/`,
copies `packaging/debian/` into that tree as the conventional top-level
`debian/` directory, and runs `dpkg-buildpackage` there. This keeps all
repository packaging sources under `packaging/` while still using standard
Debian package tooling.

### Build

```bash
sh packaging/build-deb.sh
```

Artifacts are copied to:

```text
dist/deb/
```

### Install

```bash
sudo apt install ./dist/deb/tpm-luks-tool_*_all.deb
```

`/etc/tpm-luks.toml` is a normal Debian conffile. `apt remove` preserves
administrator configuration; `apt purge` may remove it. Runtime
`/var/lib/tpm-luks` state/history are not package-owned and are therefore not
removed by either operation.

## Containerized builds

Both package formats can be built on any Linux distribution with a compatible
OCI container engine. The host does not need the RPM or Debian build toolchain.

The wrappers select the container engine in this order:

1. `CONTAINER_ENGINE`, when explicitly set;
2. Podman, when available;
3. Docker, when available.

If SELinux is enforcing, the repository bind mount automatically receives the
private `:Z` relabel option. This keeps the wrappers suitable for Fedora and
other SELinux-enforcing hosts without making Fedora a host requirement.

### RPM build container

```bash
./packaging/build-rpm-container.sh
```

Default build image:

```text
fedora:latest
```

The Fedora image is the RPM build environment only; the host distribution is
irrelevant. The wrapper installs the RPM build dependencies inside an ephemeral
container and delegates to `packaging/build-rpm.sh`.

Artifacts are written back to:

```text
dist/rpm/
```

### DEB build container

```bash
./packaging/build-deb-container.sh
```

Default build image:

```text
debian:12
```

The Debian image is the DEB build environment only. The wrapper installs the
Debian build dependencies inside an ephemeral container and delegates to
`packaging/build-deb.sh`.

Artifacts are written back to:

```text
dist/deb/
```

Alternative engines can be selected explicitly:

```bash
CONTAINER_ENGINE=docker ./packaging/build-rpm-container.sh
CONTAINER_ENGINE=docker ./packaging/build-deb-container.sh
```

Build images can also be overridden independently of the host distribution:

```bash
RPM_CONTAINER_IMAGE=fedora:44 ./packaging/build-rpm-container.sh
DEB_CONTAINER_IMAGE=ubuntu:24.04 ./packaging/build-deb-container.sh
```

The native build scripts remain authoritative. The container wrappers only
supply isolated, reproducible build environments around them.

## Versioning

The upstream version in `pyproject.toml` must match:

- `Version:` in `packaging/rpm/tpm-luks-tool.spec`,
- the upstream part of the newest version in `packaging/debian/changelog`.

The build helpers fail early when these values differ.

Native package revisions are independent of the upstream application version:

```text
RPM: 0.4.0-2
DEB: 0.4.0-2
```

A packaging-only change can increment the native release/revision while keeping
the application version unchanged.

## CI

The package workflow builds and inspects packages on:

- Fedora current,
- Rocky Linux 9,
- Debian 12,
- Ubuntu 24.04.

The resulting RPM/DEB files are uploaded as workflow artifacts for inspection.
Package builds run the same unit test suite as the source CI.

## Tagged releases

The `Release` workflow runs on pushed `v*` tags. It accepts stable tags in
`vMAJOR.MINOR.PATCH` form only. For example, `v0.4.0` must match upstream
`0.4.0` in `pyproject.toml` and both native package definitions. It does not
rewrite package metadata: RPM release `2%{?dist}` and DEB revision `2` remain
intact. A tag such as `v0.4.0-2` is not an upstream release tag.

Release procedure:

1. Merge the reviewed release automation and any intended release changes.
2. Identify the exact `main` commit to release. Wait for its `CI` workflow to
   succeed, including the `Compile` and `Unit tests` steps in the `test` job.
   If needed, rerun the failed/cancelled job or run `CI` manually on `main`.
   A successful pull-request run or a run with no executed test steps is
   insufficient. Do not create or push the tag before this validation.
3. After release approval, create and push the matching version tag on that
   exact validated commit. This triggers publication automatically; there is
   no separate approval prompt in the workflow.
4. Review the resulting release and its linked build run.

The workflow requires the tagged commit to be in `main` history and the newest
`CI` run for that exact commit on `main` (push or manual) to have succeeded.
It also checks the latest attempt's job and step results. It fails immediately
if that evidence is absent; it does not wait for CI or accept a different
commit's success.

After validation, it calls the existing native package workflow from the same
commit, rebuilding and smoke-testing Fedora, Rocky Linux 9, Debian 12, and
Ubuntu 24.04 packages. The original pull-request and manual package triggers
remain available. Release builds use the triggering commit explicitly and
download only artifacts from their own run; earlier pull-request artifacts
are never promoted to releases.

Each release contains four binary packages and `SHA256SUMS`. Asset filenames
are prefixed with `rpm-fedora`, `rpm-rocky9`, `deb-debian12`, or
`deb-ubuntu2404` to prevent collisions, particularly between the identical
Debian/Ubuntu package filenames. Only download the package for your target
distribution. Prefixes do not change the package's internal identity or version.
Source RPMs and Debian build metadata remain in the workflow artifacts.

### Authenticate and verify downloads

The [v0.4.0 release](https://github.com/dryaka/tpm-luks-tool/releases/tag/v0.4.0),
published on October 13, 2026, also has `SHA256SUMS.asc`, uploaded manually by
`dryaka` on October 14. This is an ASCII-armored detached OpenPGP signature of
`SHA256SUMS`; it contains neither the manifest nor a public key. The following
procedure also applies to later releases that provide the same signature format.
The current release workflow generates and publishes `SHA256SUMS` but does not
automatically generate or upload GPG signatures. Check each release's assets;
do not assume that every release has a signature.

#### Obtain and authenticate the public key

Public keys associated with the maintainer's GitHub account can be downloaded
from [github.com/dryaka.gpg](https://github.com/dryaka.gpg). Inspection on
October 15, 2026 found a key there that successfully verifies the v0.4.0
manifest signature, with these fingerprints:

| Key | Full fingerprint |
| --- | --- |
| Primary key | `A2EE 15E1 3325 902D 5906 4AB8 7955 EAD7 8B5A F90A` |
| v0.4.0 signing subkey | `2B54 E1F3 A3CA 0D09 AE83 6B52 B77A FFD9 EB8D E00F` |

These are observed fingerprints, not an independently authenticated declaration
of the project's release-signing key. No separate authoritative release-key
fingerprint announcement or project key-distribution location was established
from the repository documentation or release metadata. Before trusting the key,
confirm its full primary fingerprint and its authorization for release signing
with the maintainer through an independently authenticated channel, such as an
already verified contact. A key downloaded from GitHub, a keyserver search,
a matching name/email, or the issuer fingerprint in the signature alone does
not establish that trust. If you cannot confirm it, stop: you cannot claim to
have authenticated the download's origin.

Download the key and inspect the primary and subkey fingerprints before import:

```bash
curl -fsSL https://github.com/dryaka.gpg -o maintainer-public-keys.asc
gpg --show-keys --with-subkey-fingerprint maintainer-public-keys.asc
# Continue only after independent fingerprint and release-signing confirmation.
gpg --import maintainer-public-keys.asc
```

The endpoint may change or contain multiple keys. Importing a key does not make
it trusted. For later releases, confirm any replacement key or signing subkey
rather than accepting it solely because it is served by the same endpoint.

#### Verify the manifest, then the packages

Download `SHA256SUMS.asc`, `SHA256SUMS`, and the packages from the same release
into one directory, preserving their asset filenames. With GnuPG installed and
the authenticated public key imported, first run:

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS
```

Require a successful exit and a good signature from the expected key, including
its authorized signing subkey. A `Good signature` message establishes that the
manifest matches the signature made by that key; the independent fingerprint
check establishes whose key you trust. GnuPG may still warn that the key is not
certified with a trusted signature if you have not recorded that trust locally.
Do not suppress the warning by assigning arbitrary ownertrust. If the key is
missing, unexpected, revoked, or expired, or verification fails, stop and
resolve the problem before installing any package.

Only after authenticating the manifest, check the package hashes:

```bash
sha256sum -c SHA256SUMS
```

The manifest lists all four packages. Download all four for the command above
to complete without missing-file errors, and require every entry to report
`OK`. If you downloaded only your target distribution's package, use
`sha256sum --ignore-missing -c SHA256SUMS` instead and require that exact package
to report `OK`; skipped entries have not been checked.

The GPG signature authenticates the checksum manifest, and the SHA-256 checks
establish that the downloaded packages match that manifest. This is separate
from native RPM package signatures or DEB/APT signing mechanisms: it does not
embed signatures in the packages or configure package-manager trust. A checksum
check alone detects changed downloads but does not authenticate their origin.

Release notes record the full source commit and link to the build run. Only the
publish job receives repository write permission. Before creating the release it
checks that the remote tag still resolves to the triggering commit. All files
are uploaded to a draft before publication. Existing releases are never
overwritten. If upload or publication fails, inspect and remove only the
incomplete draft before rerunning; never delete a published release or move a
version tag to retry.

For the first release, PR #14's successful package run on `bd7f548` is not
validation of merged `main` commit `bf3def4`. The initially cancelled
post-merge run `37363730399` is likewise insufficient until its test job
actually succeeds. Merging this automation creates another commit, which
must itself pass CI before it can be tagged.

## License and authorship

The project is licensed under the GNU General Public License version 3 or later
(`GPL-3.0-or-later`).

Author and copyright holder:

```text
Aleš Dryák <ales.dryak@volny.cz>
Copyright (C) 2026 Aleš Dryák
```

RPM uses the SPDX expression `GPL-3.0-or-later`. Debian copyright metadata uses
the conventional Debian short form `GPL-3+` for the same version-3-or-later
grant. The full license text is stored in the repository as `LICENSE`.

## Glossary

**CI** — Continuous integration: automated compilation, tests, and package checks.

**SHA-256** — Secure Hash Algorithm with a 256-bit digest, used for the
download checksums in `SHA256SUMS`.

**RPM** — RPM Package Manager package format used by Fedora, Rocky Linux, Red
Hat Enterprise Linux, and related distributions.

**DEB** — Debian binary package format used by Debian, Ubuntu, and related
distributions.

**PEP 517** — Python Packaging Authority standard interface between a Python
project and its build backend.

**Conffile** — A package-managed configuration file for which the package
manager preserves local administrator modifications according to distribution
policy.
