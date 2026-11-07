from __future__ import annotations

import argparse
import getpass
import hmac
import json
import os
import pwd
import sqlite3
import stat
import sys
import uuid
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from config import ConfigError, from_env
from kill_switch import Level, engage, read_state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bantis response controller: manual review, kill switch and status.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="Show the effective kill switch state.")
    kill = commands.add_parser("kill", help="Engage the kill switch. No approval needed.")
    kill.add_argument("--level", choices=[Level.AUTO_OFF.value, Level.EXECUTION_OFF.value], default=Level.EXECUTION_OFF.value)
    kill.add_argument("--ai-off", action="store_true", help="Also stop the AI Copilot's model calls.")
    kill.add_argument("--reason", required=True)
    emergency = commands.add_parser("emergency-stop", help="Immediately stop all execution and AI calls. No approval needed.")
    emergency.add_argument("--reason", default="Emergency stop requested by operator")
    emergency.set_defaults(level=Level.EXECUTION_OFF.value, ai_off=True)
    commands.add_parser("emergency-button", help="Open a local emergency stop button (requires Tk).")
    commands.add_parser("promotion-hold", help="Show whether a CI promotion hold (quarantine) is active. Read-only.")
    propose = commands.add_parser("propose", help="Queue a policy proposal from a JSON file; never executes it.")
    propose.add_argument("file", type=Path)
    commands.add_parser("pending", help="List proposals awaiting manual review.")
    auto = commands.add_parser("auto-run", help="Run one queued proposal within the configured automatic scope; no approval prompt.")
    auto.add_argument("action_id")
    sync = commands.add_parser("sync", help="Join detection incidents to recorded Copilot review context and queue policy proposals.")
    sync.add_argument("--detection-url", default=os.environ.get("DETECTION_ENGINE_URL", "http://127.0.0.1:8001"))
    sync.add_argument("--decision-log", type=Path, default=os.environ.get("BANTIS_DECISION_LOG"))
    sync.add_argument("--since", required=True, help="Timezone-aware ISO timestamp; explicit backlog boundary.")
    sync.add_argument("--execute", action="store_true", help="Also attempt pending proposals through the bounded automatic runner.")
    show = commands.add_parser("show", help="Show a proposal, its hash, status and decision history.")
    show.add_argument("action_id")
    for decision in ("approve", "modify", "dismiss"):
        command = commands.add_parser(decision, help=f"{decision.capitalize()} one exact proposal (operator authentication required).")
        command.add_argument("action_id")
        command.add_argument("hash_prefix", help="At least the first 12 characters of the displayed proposal hash.")
        if decision != "approve":
            command.add_argument("--reason", required=True)
        if decision == "modify":
            command.add_argument("--params-file", type=Path, required=True, help="JSON object replacing the action parameters.")
    audit = commands.add_parser("audit", help="Export the verified audit trail as JSON lines.")
    audit.add_argument("--action-id")
    audit.add_argument("--actor", help="Filter by executor, initiating operator or reviewer.")
    verify = commands.add_parser("audit-verify", help="Verify journal integrity and print its checkpoint.")
    verify.add_argument("--expected-head", help="Compare with a previously trusted checkpoint hash.")
    args = parser.parse_args(argv)

    if args.command == "promotion-hold":
        return _show_promotion_hold()
    if args.command == "emergency-button":
        from emergency_button import show_button

        return show_button(lambda: main(["emergency-stop"]))

    try:
        # A broken action configuration must never prevent an emergency stop.
        if args.command in {"kill", "emergency-stop"}:
            config = from_env({"BANTIS_STATE_DIR": os.environ.get("BANTIS_STATE_DIR", "")})
        else:
            config = from_env()
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return 2

    if args.command in {"propose", "pending", "show", "approve", "modify", "dismiss", "audit", "audit-verify", "auto-run", "sync"}:
        return _review(args, config)

    if args.command in {"kill", "emergency-stop"}:
        actor = pwd.getpwuid(os.getuid()).pw_name
        try:
            engage(config.state_dir, Level(args.level), args.reason, actor, ai_off=args.ai_off)
        except (ValueError, OSError) as exc:
            print(f"Could not engage kill switch: {exc}", file=sys.stderr)
            return 2
        state = read_state(config.state_dir)
        print(f"Kill switch engaged: {state.level.value}; AI {'off' if state.ai_off else 'on'}", flush=True)
        # Emergency stopping must work even when the journal is unavailable.
        try:
            from approval_flow import ReviewStore

            with closing(ReviewStore(config.state_dir / "reviews.sqlite3")) as store:
                store.record({"action_id": f"kill_{uuid.uuid4().hex}", "event": "kill_switch_engaged",
                              "actor": actor, "at": datetime.now(UTC).isoformat(),
                              "level": state.level.value, "ai_off": state.ai_off, "reason": args.reason})
        except (ValueError, OSError, sqlite3.Error) as exc:
            print(f"Kill switch engaged; could not audit engagement: {exc}", file=sys.stderr)
            return 1
        return 0

    state = read_state(config.state_dir)
    print(f"level: {state.level.value}")
    print(f"ai: {'off' if state.ai_off else 'on'}")
    for reason in state.reasons:
        print(f"  {reason}")
    print(f"enabled actions: {', '.join(sorted(config.enabled_actions)) or 'none'}")
    print(f"mode: {'dry run' if config.dry_run else 'LIVE'}")
    print(f"automatic action: {config.automatic_action or 'none (approval required)'}")
    if config.automatic_action:
        print(f"automatic scope: {config.automatic_repo}; policy: {config.automatic_policy_rule}")
        print(f"automatic limit: {config.automatic_max_per_hour} attempts per rolling hour; one per incident")
    return 0


def _authenticate() -> str:
    """Host identity plus a separate, operator-owned secret; never a CLI argument."""
    secret_path = os.environ.get("RESPONSE_APPROVER_SECRET_FILE")
    if not secret_path:
        raise ValueError("RESPONSE_APPROVER_SECRET_FILE must name this operator's private secret file")
    with Path(secret_path).open() as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("approver secret must be an operator-owned file with mode 0600 or 0400")
        expected = source.read().strip()
    if not expected:
        raise ValueError("approver secret file is empty")
    supplied = getpass.getpass("Approver secret: ")
    if not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise ValueError("operator authentication failed")
    return pwd.getpwuid(os.getuid()).pw_name


def _review(args, config) -> int:
    from approval_flow import ApprovalFlow, ReviewStore
    from executor import Executor
    from models import Proposal, Status
    from wiring import build_registry

    try:
        actor = _authenticate() if args.command in {"approve", "modify", "dismiss"} else None
        registry = build_registry()
        with closing(ReviewStore(config.state_dir / "reviews.sqlite3")) as store:
            flow = ApprovalFlow(store, Executor(registry, config, store), registry)
            if args.command == "audit":
                for entry in store.audit(action_id=args.action_id, actor=args.actor):
                    print(json.dumps(entry, sort_keys=True))
            elif args.command == "sync":
                from bridge import sync_incidents
                from incident_client import IncidentClient

                since = datetime.fromisoformat(args.since)
                if since.tzinfo is None:
                    raise ValueError("--since must include a timezone")
                reports = sync_incidents(IncidentClient(args.detection_url), flow, state_dir=config.state_dir,
                                         decision_log=args.decision_log, since=since, execute=args.execute)
                print(json.dumps(reports, indent=2))
                if any(r.get("outcome", {}).get("status") in {Status.FAILED, Status.REFUSED, Status.INVALIDATED} for r in reports):
                    return 1
            elif args.command == "audit-verify":
                print(json.dumps(store.verify(args.expected_head), sort_keys=True))
            elif args.command == "propose":
                proposal = flow.submit(Proposal.model_validate_json(args.file.read_text()),
                                       actor=pwd.getpwuid(os.getuid()).pw_name)
                _print_proposal(proposal, "pending")
            elif args.command == "pending":
                proposals = store.pending()
                for proposal in proposals:
                    print(f"{proposal.action_id}  {proposal.type}  {proposal.proposal_hash[:12]}  expires {proposal.expires_at.isoformat()}")
                if not proposals:
                    print("No pending proposals.")
            elif args.command == "show":
                proposal, status = store.get(args.action_id)
                _print_proposal(proposal, status)
                print(json.dumps({"context": store.context(args.action_id), "history": store.history(args.action_id)}, indent=2))
            elif args.command == "approve":
                outcome = flow.approve(args.action_id, args.hash_prefix, actor)
                print(outcome.model_dump_json(indent=2))
                return 0 if outcome.status in {Status.SUCCEEDED, Status.DRY_RUN, Status.AWAITING_APPROVAL} else 1
            elif args.command == "auto-run":
                outcome = flow.run_automatic(args.action_id)
                print(outcome.model_dump_json(indent=2))
                return 0 if outcome.status in {Status.SUCCEEDED, Status.DRY_RUN} else 1
            elif args.command == "modify":
                params = json.loads(args.params_file.read_text())
                if not isinstance(params, dict):
                    raise ValueError("parameters must be a JSON object")
                proposal = flow.modify(args.action_id, args.hash_prefix, actor, params, args.reason)
                _print_proposal(proposal, "pending")
                print("Previous proposal closed; fresh approval required.")
            else:
                flow.dismiss(args.action_id, args.hash_prefix, actor, args.reason)
                print(f"{args.action_id}: dismissed; no action executed.")
        return 0
    except (ValueError, OSError, sqlite3.Error, EOFError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


def _print_proposal(proposal, status: str) -> None:
    print(json.dumps({**proposal.model_dump(mode="json"), "proposal_hash": proposal.proposal_hash,
                      "status": status}, indent=2))


def _show_promotion_hold() -> int:
    from actions.promotion_hold import HOLD_VARIABLE
    from github_client import GitHubError
    from wiring import promotion_client

    try:
        client = promotion_client()
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    if client is None:
        print("RESPONSE_GITHUB_REPO and RESPONSE_GITHUB_TOKEN_PROMOTION are not set", file=sys.stderr)
        return 2
    try:
        value = client.get(HOLD_VARIABLE)
    except GitHubError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"{client.repo}: " + (f"HELD — {value}" if value is not None else "no hold; promotions run normally"))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())