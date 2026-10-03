from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class CommandError(RuntimeError):
    def __init__(self, result: CommandResult):
        message = result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}"
        super().__init__(f"command failed ({' '.join(result.argv)}): {message}")
        self.result = result


class Runner:
    def run(
        self,
        argv: Sequence[str],
        *,
        check: bool = True,
        timeout: float | None = 20,
        capture_output: bool = True,
    ) -> CommandResult:
        args = tuple(str(item) for item in argv)
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        try:
            completed = subprocess.run(
                args,
                check=False,
                capture_output=capture_output,
                text=True,
                env=env,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            result = CommandResult(args, 124, exc.stdout or "", f"command timed out after {exc.timeout}s")
            raise CommandError(result) from exc
        result = CommandResult(
            args,
            completed.returncode,
            completed.stdout or "",
            completed.stderr or "",
        )
        if check and result.returncode != 0:
            raise CommandError(result)
        return result
