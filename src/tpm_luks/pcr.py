from __future__ import annotations

import re
from pathlib import Path

from .runner import Runner


_PCR_LINE = re.compile(r"^\s*(\d+)\s+\S+\s+([0-9a-fA-F]{64})\s*$")


class PCRReadError(RuntimeError):
    pass


class PCRReader:
    def __init__(self, runner: Runner):
        self.runner = runner

    def read(self, pcrs: tuple[int, ...], bank: str) -> dict[int, str]:
        if bank != "sha256":
            raise PCRReadError(f"unsupported PCR bank: {bank}")
        result = self.runner.run(["systemd-analyze", "pcrs", *[str(pcr) for pcr in pcrs]])
        parsed = parse_systemd_analyze_pcrs(result.stdout)
        missing = [pcr for pcr in pcrs if pcr not in parsed]
        if missing:
            raise PCRReadError(f"systemd-analyze did not return PCR(s): {', '.join(map(str, missing))}")
        return {pcr: parsed[pcr] for pcr in pcrs}


def parse_systemd_analyze_pcrs(output: str) -> dict[int, str]:
    values: dict[int, str] = {}
    for line in output.splitlines():
        match = _PCR_LINE.match(line)
        if not match:
            continue
        pcr = int(match.group(1))
        value = match.group(2).lower()
        values[pcr] = value
    return values


def read_secure_boot(efivars_dir: str | Path = "/sys/firmware/efi/efivars") -> bool | None:
    directory = Path(efivars_dir)
    try:
        entries = list(directory.glob("SecureBoot-*"))
    except OSError:
        return None
    if not entries:
        return None
    try:
        raw = entries[0].read_bytes()
    except OSError:
        return None
    # efivarfs prepends four bytes of variable attributes to the variable payload.
    if len(raw) < 5:
        return None
    if raw[4] == 0:
        return False
    if raw[4] == 1:
        return True
    return None
