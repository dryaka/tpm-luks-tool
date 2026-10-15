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

Release notes record the full source commit and link to the build run. Only the
publish job receives repository write permission. Before creating the release it
checks that the remote tag still resolves to the triggering commit. All files
are uploaded to a draft before publication. Existing releases are never
overwritten. If upload or publication fails, inspect and remove only the
incomplete draft before rerunning; never delete a published release or move a
version tag to retry.

### Validate release downloads

Download the package for your distribution, `SHA256SUMS`, and
`SHA256SUMS.asc` from the same release into one directory. Preserve the asset
filenames. If the signature is absent, the following authenticity check cannot
be completed.

#### Obtain and authenticate the public key

Download [signing-keys.asc](../keys/signing-keys.asc) from the repository.
It contains the release-signing public key and the public keys that certify
its identity. The authorized release-signing primary fingerprint is:

```text
A2EE 15E1 3325 902D 5906 4AB8 7955 EAD7 8B5A F90A
```

With GnuPG installed, inspect the bundle:

```bash
gpg --show-keys --with-subkey-fingerprint signing-keys.asc
```

Confirm the full primary fingerprint through an independently trusted channel,
or validate its certifications using a certifying key you already trust.
Bundled certifier keys do not establish trust by themselves. Then import:

```bash
gpg --import signing-keys.asc
```

#### Authenticate the manifest and check the package

First verify the detached signature on the checksum manifest:

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS
```

Require a successful exit and a `Good signature` from the primary key above
or one of its valid signing subkeys. Stop if verification fails or the signer
is unexpected. An uncertified-key warning can remain after manual fingerprint
confirmation; importing a key alone does not make it trusted.

Only after successful signature verification, check the downloaded package:

```bash
sha256sum --ignore-missing -c SHA256SUMS
```

Require the exact package you intend to install to report `OK`. Missing
packages are skipped. If you downloaded every package in the manifest, use
`sha256sum -c SHA256SUMS` to check them all.

The OpenPGP signature authenticates the checksum manifest; the SHA-256 checks
verify that the packages match it. This does not provide native RPM or DEB
package signatures or configure package-manager trust.

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

**GnuPG (GPG)** — GNU Privacy Guard, the tool used to verify OpenPGP signatures.

**OpenPGP** — Open Pretty Good Privacy, the public-key signature and encryption
standard used for release authentication.

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
