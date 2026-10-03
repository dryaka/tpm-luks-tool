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


def _add_config_option(parser: argparse.ArgumentParser, *, suppress_default: bool = False) -> None:
    parser.add_argument(
        "--config",
        default=argparse.SUPPRESS if suppress_default else "/etc/tpm-luks.toml",
        metavar="PATH",
        help="policy TOML file (default: /etc/tpm-luks.toml)",
    )


def _add_state_option(parser: argparse.ArgumentParser, *, suppress_default: bool = False) -> None:
    parser.add_argument(
        "--state-dir",
        default=argparse.SUPPRESS if suppress_default else "/var/lib/tpm-luks",
        metavar="PATH",
        help="runtime state/history directory (default: /var/lib/tpm-luks)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tpm-luks",
        description="Inspect TPM2 PCR policy state and TPM-bound LUKS2 metadata.",
        epilog="Use 'tpm-luks <command> --help' for command-specific options and examples.",
    )
    _add_config_option(parser)
    _add_state_option(parser)

    sub = parser.add_subparsers(dest="command", required=True, title="commands")

    status = sub.add_parser(
        "status",
        help="show human-readable current state",
        description=(
            "Inspect the configured PCR policy, compare current PCR values with the approved "
            "state, and show LUKS2 keyslots and systemd-tpm2 token associations."
        ),
        epilog=(
            "Example:\n"
            "  sudo tpm-luks status --config ./test-policy.toml "
            "--state-dir /tmp/tpm-luks-test-state"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_config_option(status, suppress_default=True)
    _add_state_option(status, suppress_default=True)

    check = sub.add_parser(
        "check",
        help="emit machine-readable current state as JSON",
        description=(
            "Perform the same read-only inspection as 'status', but emit JSON suitable for "
            "monitoring or scripts."
        ),
        epilog=(
            "Exit codes:\n"
            "  0  current PCR policy matches approved state\n"
            "  1  configuration, command, metadata, or runtime error\n"
            "  2  PCR drift detected\n"
            "  3  no approved state exists\n"
            "  4  configured policy differs from approved policy\n"
            "\nExample:\n"
            "  sudo tpm-luks check --config ./test-policy.toml "
            "--state-dir /tmp/tpm-luks-test-state"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_config_option(check, suppress_default=True)
    _add_state_option(check, suppress_default=True)

    history = sub.add_parser(
        "history",
        help="list stored transaction manifests",
        description="List transaction manifests stored under the runtime history directory.",
        epilog="Example:\n  tpm-luks history --state-dir /var/lib/tpm-luks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_state_option(history, suppress_default=True)

    show = sub.add_parser(
        "show",
        help="show one stored transaction manifest",
        description="Display one transaction manifest as formatted JSON.",
        epilog=(
            "Example:\n"
            "  tpm-luks show 20261003T180000+0200 --state-dir /var/lib/tpm-luks"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_state_option(show, suppress_default=True)
    show.add_argument("transaction_id", metavar="TRANSACTION_ID", help="transaction identifier")

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
