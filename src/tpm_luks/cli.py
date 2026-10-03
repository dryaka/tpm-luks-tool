from __future__ import annotations

import argparse
import json
import sys

from .config import PolicyError, load_policy
from .formatting import format_check_json, format_status
from .luks import LUKSMetadataError, LUKSMetadataReader
from .models import DriftState
from .pcr import PCRReadError, PCRReader
from .runner import CommandError, Runner
from .service import collect_snapshot
from .state import StateError, StateStore


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DRIFT = 2
EXIT_UNINITIALIZED = 3
EXIT_POLICY_CHANGE = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tpm-luks")
    parser.add_argument("--config", default="/etc/tpm-luks.toml", help="policy TOML file")
    parser.add_argument("--state-dir", default="/var/lib/tpm-luks", help="runtime state directory")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="show human-readable current state")
    sub.add_parser("check", help="emit machine-readable current state as JSON")
    sub.add_parser("history", help="list stored transaction manifests")
    show = sub.add_parser("show", help="show one stored transaction manifest")
    show.add_argument("transaction_id")
    return parser


def _drift_exit_code(state: DriftState) -> int:
    return {
        DriftState.MATCH: EXIT_OK,
        DriftState.DRIFT: EXIT_DRIFT,
        DriftState.UNINITIALIZED: EXIT_UNINITIALIZED,
        DriftState.POLICY_CHANGE: EXIT_POLICY_CHANGE,
    }[state]


def _load_snapshot(config_path: str, state_dir: str):
    policy = load_policy(config_path)
    runner = Runner()
    store = StateStore(state_dir)
    return collect_snapshot(policy, PCRReader(runner), LUKSMetadataReader(runner), store)


def _print_history(store: StateStore) -> None:
    manifests = store.list_history()
    if not manifests:
        print("No transaction history.")
        return
    print("ID                       TYPE           STATE")
    for item in manifests:
        transaction_id = str(item.get("id", "-"))
        tx_type = str(item.get("type", "-"))
        state = str(item.get("state", "-"))
        print(f"{transaction_id:<24} {tx_type:<14} {state}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "history":
            _print_history(StateStore(args.state_dir))
            return EXIT_OK
        if args.command == "show":
            manifest = StateStore(args.state_dir).load_manifest(args.transaction_id)
            print(json.dumps(manifest, indent=2, sort_keys=True))
            return EXIT_OK

        snapshot = _load_snapshot(args.config, args.state_dir)
        if args.command == "status":
            print(format_status(snapshot))
            return EXIT_OK
        if args.command == "check":
            print(format_check_json(snapshot))
            return _drift_exit_code(snapshot.drift_state)
    except (PolicyError, StateError, PCRReadError, LUKSMetadataError, CommandError, OSError) as exc:
        print(f"tpm-luks: {exc}", file=sys.stderr)
        return EXIT_ERROR

    parser.error(f"unsupported command: {args.command}")
    return EXIT_ERROR
