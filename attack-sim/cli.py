from __future__ import annotations

import argparse
import sys

from scenarios import (
    compromised_ci_step,
    leaked_secret,
    malicious_dependency,
    noop,
    typosquatting,
)
from scenarios.base import ScenarioEnvironmentError, ScenarioStatus
from scenarios.replay import available, replay


def _cmd_list(_args: argparse.Namespace) -> int:
    # Reads class attributes only — never instantiates a scenario — so
    # this is exempt from the BANTIS_ENV guard by construction.
    for scenario_id, scenario_cls in sorted(available().items()):
        print(f"{scenario_id:<24} {scenario_cls.mitre_technique}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        result = replay(args.scenario)
    except (KeyError, ScenarioEnvironmentError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"{result.status.value}: {result.message}")
    return 1 if result.status == ScenarioStatus.ERROR else 0


def _cmd_cleanup(args: argparse.Namespace) -> int:
    scenario_cls = available().get(args.scenario)
    if scenario_cls is None:
        print(
            f"error: unknown scenario_id {args.scenario!r} — available: {sorted(available())}",
            file=sys.stderr,
        )
        return 1

    try:
        scenario_cls().cleanup()
    except ScenarioEnvironmentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"cleanup complete: {args.scenario}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attack-sim",
        description="Run and manage Bantis attack-sim scenarios.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="List available scenarios and their MITRE technique.")

    run_parser = subparsers.add_parser(
        "run", help="Run one scenario end-to-end: run() -> log_result() -> cleanup()."
    )
    run_parser.add_argument("scenario", help="Scenario id, e.g. malicious-dependency.")

    cleanup_parser = subparsers.add_parser(
        "cleanup",
        help="Force-cleanup a scenario without running it first — recovers a "
        "dirty state left by a crashed or interrupted prior run.",
    )
    cleanup_parser.add_argument("scenario", help="Scenario id, e.g. malicious-dependency.")

    return parser


_COMMANDS = {"list": _cmd_list, "run": _cmd_run, "cleanup": _cmd_cleanup}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return _COMMANDS[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())