from __future__ import annotations

import argparse
import json
import os
import sys

from .approval import ApprovalError, ApprovalInterrupted, ApprovalService
from .cleanup import CleanupError, CleanupInterrupted, CleanupService
from .config import PolicyError, load_policy
from .formatting import (
    format_approval_plan,
    format_check_json,
    format_cleanup_plan,
    format_enrollment_plan,
    format_status,
)
from .luks import LUKSMetadataError, LUKSMetadataReader
from .models import DriftState
from .pcr import PCRReadError, PCRReader
from .runner import CommandError, Runner
from .service import collect_snapshot
from .state import StateError, StateStore
from .transaction import EnrollmentError, EnrollmentInterrupted, EnrollmentService


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DRIFT = 2
EXIT_UNINITIALIZED = 3
EXIT_POLICY_CHANGE = 4

_COMMANDS = {"status", "check", "history", "show", "approve", "reenroll", "cleanup"}
_VALUE_OPTIONS = {"--config", "--state-dir"}
_HELP_OPTIONS = {"-h", "--help"}
_COMMAND_FLAGS = {
    "approve": {"--yes"},
    "reenroll": {"--yes"},
    "cleanup": {"--yes"},
}


def _active_option_positions(argv: list[str], options: set[str]) -> set[int]:
    positions: set[int] = set()
    consume_next = False
    for index, token in enumerate(argv):
        if consume_next:
            consume_next = False
            continue
        if token in _VALUE_OPTIONS:
            consume_next = True
            continue
        if any(token.startswith(f"{option}=") for option in _VALUE_OPTIONS):
            continue
        if token in options:
            positions.add(index)
    return positions


def _command_position(argv: list[str]) -> int | None:
    consume_next = False
    for index, token in enumerate(argv):
        if consume_next:
            consume_next = False
            continue
        if token in _VALUE_OPTIONS:
            consume_next = True
            continue
        if any(token.startswith(f"{option}=") for option in _VALUE_OPTIONS):
            continue
        if token in _COMMANDS:
            return index
    return None


def _normalize_help_position(argv: list[str]) -> list[str]:
    command_position = _command_position(argv)
    if command_position is None:
        return argv
    help_positions = _active_option_positions(argv, _HELP_OPTIONS)
    if not help_positions or all(position > command_position for position in help_positions):
        return argv
    help_option = argv[min(help_positions)]
    normalized = [token for index, token in enumerate(argv) if index not in help_positions]
    command_position = _command_position(normalized)
    assert command_position is not None
    normalized.insert(command_position + 1, help_option)
    return normalized


def _normalize_command_flags(argv: list[str]) -> list[str]:
    command_position = _command_position(argv)
    if command_position is None:
        return argv
    command = argv[command_position]
    allowed = _COMMAND_FLAGS.get(command, set())
    if not allowed:
        return argv
    positions = _active_option_positions(argv, allowed)
    before = sorted(position for position in positions if position < command_position)
    if not before:
        return argv
    flags = [argv[position] for position in before]
    normalized = [token for index, token in enumerate(argv) if index not in set(before)]
    command_position = _command_position(normalized)
    assert command_position is not None
    for offset, flag in enumerate(flags, start=1):
        normalized.insert(command_position + offset, flag)
    return normalized


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
        description="Inspect and safely manage TPM2 PCR-bound LUKS2 enrollments.",
        epilog=(
            "Applicable options may appear before or after the command. If a command is named, "
            "-h/--help shows help for that command regardless of position."
        ),
    )
    _add_config_option(parser)
    _add_state_option(parser)
    sub = parser.add_subparsers(dest="command", required=True, title="commands")

    status = sub.add_parser(
        "status",
        help="show human-readable current state",
        description=(
            "Inspect the configured PCR policy, compare current PCR values with the operational "
            "baseline and desired target, and show LUKS2 keyslots and systemd-tpm2 associations."
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
            "  0  current PCR state matches operational baseline\n"
            "  1  configuration, command, metadata, or runtime error\n"
            "  2  PCR drift from operational baseline\n"
            "  3  no operational baseline exists\n"
            "  4  configured policy differs from operational baseline\n"
            "\nExample:\n"
            "  sudo tpm-luks check --config ./test-policy.toml "
            "--state-dir /tmp/tpm-luks-test-state"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_config_option(check, suppress_default=True)
    _add_state_option(check, suppress_default=True)

    approve = sub.add_parser(
        "approve",
        help="approve the current PCR state as the desired target",
        description=(
            "Record an explicit trust decision for the currently observed PCR values. "
            "This command does not modify LUKS metadata; reenroll performs the subsequent "
            "volume reconciliation."
        ),
        epilog=(
            "Approval is required when current PCR values differ from the operational baseline.\n\n"
            "Example:\n"
            "  sudo tpm-luks approve --config /etc/tpm-luks.toml"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_config_option(approve, suppress_default=True)
    _add_state_option(approve, suppress_default=True)
    approve.add_argument(
        "--yes",
        action="store_true",
        help="approve the current PCR values without interactive confirmation",
    )

    reenroll = sub.add_parser(
        "reenroll",
        help="add and verify replacement TPM enrollments",
        description=(
            "Reconcile every configured volume to the already approved PCR target. "
            "When PCR drift is awaiting approval, run 'approve' first. If there is no desired "
            "target and the current PCR state matches the operational baseline, reenroll acts as "
            "a repair/reconciliation operation."
        ),
        epilog=(
            "The command may prompt for an existing LUKS passphrase/recovery key for each volume.\n"
            "Successful enrollment ends in PENDING_BOOT_TEST; obsolete TPM slots remain until the "
            "Phase 3 cleanup command is run after a successful reboot.\n\n"
            "Example:\n"
            "  sudo tpm-luks reenroll --config /etc/tpm-luks.toml"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_config_option(reenroll, suppress_default=True)
    _add_state_option(reenroll, suppress_default=True)
    reenroll.add_argument("--yes", action="store_true", help="skip the interactive confirmation")

    cleanup = sub.add_parser(
        "cleanup",
        help="remove obsolete TPM enrollments after a successful boot test",
        description=(
            "Verify the pending transaction and current PCR state, identify only the obsolete "
            "TPM token/keyslot pairs proven by the transaction evidence, show the exact targets, "
            "then remove them after explicit confirmation."
        ),
        epilog=(
            "The operator confirmation attests that the system successfully rebooted and unlocked "
            "with the replacement TPM policy. For transactions created by this version, the tool "
            "also verifies that the boot ID changed since enrollment.\n\n"
            "Example:\n"
            "  sudo tpm-luks cleanup --config /etc/tpm-luks.toml"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_config_option(cleanup, suppress_default=True)
    _add_state_option(cleanup, suppress_default=True)
    cleanup.add_argument("--yes", action="store_true", help="skip the interactive confirmation")

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
        epilog="Example:\n  tpm-luks show 20261003T180000Z --state-dir /var/lib/tpm-luks",
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
    print("ID                       TYPE                STATE")
    for item in manifests:
        transaction_id = str(item.get("id", "-"))
        tx_type = str(item.get("type", "-"))
        state = str(item.get("state", "-"))
        print(f"{transaction_id:<24} {tx_type:<19} {state}")


def _run_approve(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise ApprovalError("approve must run as root")
    policy = load_policy(args.config)
    runner = Runner()
    store = StateStore(args.state_dir)
    service = ApprovalService(
        policy,
        PCRReader(runner),
        LUKSMetadataReader(runner),
        store,
    )
    plan = service.prepare()
    print(format_approval_plan(plan))
    if not args.yes:
        if not sys.stdin.isatty():
            raise ApprovalError(
                "interactive confirmation requires a TTY; use --yes to approve explicitly"
            )
        try:
            answer = input("Approve current PCR values as the desired target? [y/N] ").strip().lower()
        except KeyboardInterrupt as exc:
            raise ApprovalInterrupted("interrupted before approval; no trust state changed") from exc
        if answer not in {"y", "yes"}:
            print("Approval cancelled; no trust state or LUKS metadata was changed.")
            return EXIT_OK
    manifest = service.execute(plan)
    print(f"Transaction {manifest['id']}: {manifest['state']}")
    print("Run 'tpm-luks reenroll' to reconcile configured volumes to the approved target.")
    return EXIT_OK


def _run_reenroll(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise EnrollmentError("reenroll must run as root")
    policy = load_policy(args.config)
    runner = Runner()
    store = StateStore(args.state_dir)
    service = EnrollmentService(policy, runner, PCRReader(runner), LUKSMetadataReader(runner), store)
    plan = service.prepare()
    print(format_enrollment_plan(plan))
    if not args.yes:
        if not sys.stdin.isatty():
            service.cancel(plan)
            raise EnrollmentError("interactive confirmation requires a TTY; use --yes to confirm reconciliation")
        try:
            answer = input("Proceed with TPM enrollment reconciliation? [y/N] ").strip().lower()
        except KeyboardInterrupt as exc:
            service.cancel(plan)
            raise EnrollmentInterrupted("interrupted before enrollment; transaction unchanged") from exc
        if answer not in {"y", "yes"}:
            service.cancel(plan)
            print("Cancelled; no LUKS metadata was changed.")
            return EXIT_OK
    print("Enrollment may now request an existing LUKS passphrase/recovery key for each volume.")
    manifest = service.execute(plan)
    for name, volume in manifest.get("volumes", {}).items():
        result = volume.get("enrollment_result")
        if result == "ADDED":
            print(
                f"{name}: added TPM token {volume.get('new_token')} "
                f"on keyslot {volume.get('new_keyslot')}"
            )
        elif result == "ALREADY_PRESENT":
            print(f"{name}: equivalent TPM policy already present; no metadata change")
    print(f"Transaction {plan.transaction_id}: {manifest['state']}")
    print("Reboot and verify TPM unlock before any obsolete TPM enrollment is removed.")
    return EXIT_OK


def _run_cleanup(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise CleanupError("cleanup must run as root")
    policy = load_policy(args.config)
    runner = Runner()
    store = StateStore(args.state_dir)
    service = CleanupService(policy, runner, PCRReader(runner), LUKSMetadataReader(runner), store)
    plan = service.prepare()
    print(format_cleanup_plan(plan))
    if not args.yes:
        if not sys.stdin.isatty():
            raise CleanupError("interactive confirmation requires a TTY; use --yes to approve explicitly")
        try:
            answer = input(
                "Confirm successful reboot/TPM unlock and remove the listed obsolete enrollments? [y/N] "
            ).strip().lower()
        except KeyboardInterrupt as exc:
            raise CleanupInterrupted("interrupted before cleanup; transaction unchanged") from exc
        if answer not in {"y", "yes"}:
            print("Cleanup cancelled; transaction remains pending.")
            return EXIT_OK
    manifest = service.execute(plan)
    print(f"Transaction {plan.transaction_id}: {manifest['state']}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    normalized = _normalize_command_flags(_normalize_help_position(raw_argv))
    args = parser.parse_args(normalized)
    try:
        if args.command == "history":
            _print_history(StateStore(args.state_dir))
            return EXIT_OK
        if args.command == "show":
            manifest = StateStore(args.state_dir).load_manifest(args.transaction_id)
            print(json.dumps(manifest, indent=2, sort_keys=True))
            return EXIT_OK
        if args.command == "approve":
            return _run_approve(args)
        if args.command == "reenroll":
            return _run_reenroll(args)
        if args.command == "cleanup":
            return _run_cleanup(args)

        snapshot = _load_snapshot(args.config, args.state_dir)
        if args.command == "status":
            print(format_status(snapshot))
            return EXIT_OK
        if args.command == "check":
            print(format_check_json(snapshot))
            return _drift_exit_code(snapshot.drift_state)
    except (ApprovalInterrupted, EnrollmentInterrupted, CleanupInterrupted) as exc:
        print(f"\ntpm-luks: {exc}", file=sys.stderr)
        return 130
    except KeyboardInterrupt:
        print("\ntpm-luks: interrupted", file=sys.stderr)
        return 130
    except (
        ApprovalError,
        PolicyError,
        StateError,
        PCRReadError,
        LUKSMetadataError,
        CommandError,
        EnrollmentError,
        CleanupError,
        OSError,
    ) as exc:
        print(f"tpm-luks: {exc}", file=sys.stderr)
        return EXIT_ERROR

    parser.error(f"unsupported command: {args.command}")
    return EXIT_ERROR
