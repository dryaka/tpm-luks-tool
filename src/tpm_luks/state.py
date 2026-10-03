from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import ApprovedState


class StateError(RuntimeError):
    pass


_TRANSACTION_ID = re.compile(r"^[A-Za-z0-9._:+-]+$")


class StateStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    @property
    def state_path(self) -> Path:
        return self.root / "state.json"

    @property
    def history_path(self) -> Path:
        return self.root / "history"

    def load_approved_state(self) -> ApprovedState | None:
        if not self.state_path.exists():
            return None
        data = self._load_json(self.state_path)
        try:
            policy_name = data["policy_name"]
            bank = data["bank"]
            raw_pcrs = data["pcrs"]
            raw_values = data["values"]
        except KeyError as exc:
            raise StateError(f"state file missing field: {exc.args[0]}") from exc
        if not isinstance(policy_name, str) or not isinstance(bank, str):
            raise StateError("state policy_name and bank must be strings")
        if not isinstance(raw_pcrs, list) or any(type(item) is not int for item in raw_pcrs):
            raise StateError("state pcrs must be an integer array")
        if not isinstance(raw_values, dict):
            raise StateError("state values must be an object")
        values: dict[int, str] = {}
        for pcr in raw_pcrs:
            value = raw_values.get(str(pcr))
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
                raise StateError(f"state value for PCR {pcr} must be a SHA-256 hex digest")
            values[pcr] = value.lower()
        return ApprovedState(policy_name=policy_name, bank=bank, pcrs=tuple(sorted(raw_pcrs)), values=values)

    def list_history(self) -> list[dict[str, Any]]:
        if not self.history_path.exists():
            return []
        manifests: list[dict[str, Any]] = []
        for path in sorted(self.history_path.glob("*/manifest.json"), reverse=True):
            data = self._load_json(path)
            data.setdefault("id", path.parent.name)
            manifests.append(data)
        return manifests

    def load_manifest(self, transaction_id: str) -> dict[str, Any]:
        if not _TRANSACTION_ID.fullmatch(transaction_id):
            raise StateError("invalid transaction id")
        path = self.history_path / transaction_id / "manifest.json"
        if not path.exists():
            raise StateError(f"transaction not found: {transaction_id}")
        return self._load_json(path)

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise StateError(f"cannot read {path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise StateError(f"invalid JSON in {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise StateError(f"JSON root in {path} must be an object")
        return data
