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

**RPM** — RPM Package Manager package format used by Fedora, Rocky Linux, Red
Hat Enterprise Linux, and related distributions.

**DEB** — Debian binary package format used by Debian, Ubuntu, and related
distributions.

**PEP 517** — Python Packaging Authority standard interface between a Python
project and its build backend.

**Conffile** — A package-managed configuration file for which the package
manager preserves local administrator modifications according to distribution
policy.
