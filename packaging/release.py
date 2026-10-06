"""Validate release metadata and stage distribution-specific binary assets."""

import hashlib
from pathlib import Path
import re
import shutil
import sys
import tomllib


def validate(tag: str, root: Path = Path('.')) -> None:
    version = tomllib.loads((root / 'pyproject.toml').read_text())['project']['version']
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag) or tag != f'v{version}':
        raise ValueError(f'tag {tag!r} must be v{version} (stable upstream version)')
    spec = (root / 'packaging/rpm/tpm-luks-tool.spec').read_text()
    rpm_version = re.search(r'^Version:\s*(\S+)\s*$', spec, re.MULTILINE)
    rpm_release = re.search(r'^Release:\s*(\S+)\s*$', spec, re.MULTILINE)
    changelog = (root / 'packaging/debian/changelog').read_text().splitlines()[0]
    deb = re.fullmatch(r'tpm-luks-tool \(([^()]+)\) .+', changelog)
    if not rpm_version or rpm_version[1] != version or not rpm_release:
        raise ValueError('RPM metadata must match upstream and include a native release')
    if not deb or '-' not in deb[1] or deb[1].rsplit('-', 1)[0] != version or not deb[1].rsplit('-', 1)[1]:
        raise ValueError('DEB metadata must match upstream and include a native revision')
    print(f'Upstream {version}; RPM {version}-{rpm_release[1]}; DEB {deb[1]}')


def stage(artifacts: Path, destination: Path) -> None:
    targets = {
        'rpm-fedora': 'tpm-luks-tool-*.noarch.rpm',
        'rpm-rocky9': 'tpm-luks-tool-*.noarch.rpm',
        'deb-debian12': 'tpm-luks-tool_*_all.deb',
        'deb-ubuntu2404': 'tpm-luks-tool_*_all.deb',
    }
    packages = []
    for target, pattern in targets.items():
        matches = list((artifacts / target).glob(pattern))
        if len(matches) != 1 or not matches[0].is_file() or matches[0].is_symlink() or matches[0].stat().st_size == 0:
            raise ValueError(f'{target}: expected exactly one nonempty binary package')
        packages.append((target, matches[0]))
    destination.mkdir()  # Never mix with stale output from an earlier build.
    checksums = []
    for target, source in packages:
        name = f'{target}-{source.name}'
        output = destination / name
        shutil.copyfile(source, output)
        checksums.append(f'{hashlib.sha256(output.read_bytes()).hexdigest()}  {name}\n')
    (destination / 'SHA256SUMS').write_text(''.join(sorted(checksums)))


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == 'validate':
        validate(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == 'stage':
        stage(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        sys.exit('usage: release.py validate TAG | stage ARTIFACTS DESTINATION')
