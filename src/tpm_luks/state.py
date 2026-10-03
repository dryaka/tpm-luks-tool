from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import ApprovedState


class StateError(RuntimeError):
    pass


_TRANSACTION_ID = re.compile(r"^[A-Za-z0-9._:+-]+$")
_EVIDENCE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_ACTIVE_STATES = {"PREPARING", "PENDING_BOOT_TEST", "CLEANING", "FAILED_CLEANUP"}


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

    def write_approved_state(
        self,
        state: ApprovedState,
        *,
        transaction_id: str,
        approved_at: str,
    ) -> None:
        payload = {
            "policy_name": state.policy_name,
            "bank": state.bank,
            "pcrs": list(state.pcrs),
            "values": {str(pcr): value for pcr, value in sorted(state.values.items())},
            "approved_by_transaction": transaction_id,
            "approved_at": approved_at,
        }
        self._write_json(self.state_path, payload)

    def create_transaction(self, manifest: dict[str, Any]) -> str:
        self._ensure_private_dir(self.history_path)
        transaction_id = self._next_transaction_id()
        tx_dir = self.history_path / transaction_id
        self._ensure_private_dir(tx_dir)
        payload = dict(manifest)
        payload["id"] = transaction_id
        self.write_manifest(transaction_id, payload)
        return transaction_id

    def write_manifest(self, transaction_id: str, manifest: dict[str, Any]) -> None:
        self._validate_transaction_id(transaction_id)
        tx_dir = self.history_path / transaction_id
        self._ensure_private_dir(tx_dir)
        payload = dict(manifest)
        payload["id"] = transaction_id
        self._write_json(tx_dir / "manifest.json", payload)

    def update_manifest(self, transaction_id: str, **updates: Any) -> dict[str, Any]:
        manifest = self.load_manifest(transaction_id)
        manifest.update(updates)
        self.write_manifest(transaction_id, manifest)
        return manifest

    def write_evidence_json(self, transaction_id: str, name: str, data: Any) -> None:
        path = self._evidence_path(transaction_id, name)
        self._atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")

    def write_evidence_bytes(self, transaction_id: str, name: str, data: bytes) -> None:
        path = self._evidence_path(transaction_id, name)
        self._atomic_write_bytes(path, data)

    def list_history(self) -> list[dict[str, Any]]:
        if not self.history_path.exists():
            return []
        manifests: list[dict[str, Any]] = []
        for path in sorted(self.history_path.glob("*/manifest.json"), reverse=True):
            data = self._load_json(path)
            data.setdefault("id", path.parent.name)
            manifests.append(data)
        return manifests

    def find_active_transaction(self) -> dict[str, Any] | None:
        active = [item for item in self.list_history() if item.get("state") in _ACTIVE_STATES]
        if len(active) > 1:
            raise StateError("multiple active transactions found; manual repair is required")
        return active[0] if active else None

    def load_manifest(self, transaction_id: str) -> dict[str, Any]:
        self._validate_transaction_id(transaction_id)
        path = self.history_path / transaction_id / "manifest.json"
        if not path.exists():
            raise StateError(f"transaction not found: {transaction_id}")
        return self._load_json(path)

    def _next_transaction_id(self) -> str:
        base = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        candidate = base
        sequence = 1
        while (self.history_path / candidate).exists():
            candidate = f"{base}-{sequence:02d}"
            sequence += 1
        return candidate

    def _evidence_path(self, transaction_id: str, name: str) -> Path:
        self._validate_transaction_id(transaction_id)
        if not _EVIDENCE_NAME.fullmatch(name):
            raise StateError(f"invalid evidence file name: {name}")
        tx_dir = self.history_path / transaction_id
        self._ensure_private_dir(tx_dir)
        return tx_dir / name

    @staticmethod
    def _validate_transaction_id(transaction_id: str) -> None:
        if not _TRANSACTION_ID.fullmatch(transaction_id):
            raise StateError("invalid transaction id")

    @staticmethod
    def _ensure_private_dir(path: Path) -> None:
        try:
            if path.exists() and path.is_symlink():
                raise StateError(f"refusing symlinked state directory: {path}")
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, 0o700)
        except OSError as exc:
            raise StateError(f"cannot prepare state directory {path}: {exc}") from exc

    def _write_json(self, path: Path, data: Any) -> None:
        self._atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")

    @staticmethod
    def _atomic_write_text(path: Path, text: str) -> None:
        StateStore._atomic_write_bytes(path, text.encode("utf-8"))

    @staticmethod
    def _atomic_write_bytes(path: Path, data: bytes) -> None:
        StateStore._ensure_private_dir(path.parent)
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
                temporary = handle.name
                os.chmod(temporary, 0o600)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            os.chmod(path, 0o600)
        except OSError as exc:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
            raise StateError(f"cannot write {path}: {exc}") from exc

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
