from __future__ import annotations

import argparse
import getpass
import sys

from config import ConfigError, from_env
from kill_switch import Level, engage, read_state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bantis response controller: kill switch and status.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="Show the effective kill switch state.")
    kill = commands.add_parser("kill", help="Engage the kill switch. No approval needed.")
    kill.add_argument("--level", choices=[Level.AUTO_OFF.value, Level.EXECUTION_OFF.value], default=Level.EXECUTION_OFF.value)
    kill.add_argument("--ai-off", action="store_true", help="Also stop the AI Copilot's model calls.")
    kill.add_argument("--reason", required=True)
    args = parser.parse_args(argv)

    try:
        config = from_env()
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return 2

    if args.command == "kill":
        engage(config.state_dir, Level(args.level), args.reason, getpass.getuser(), ai_off=args.ai_off)

    state = read_state(config.state_dir)
    print(f"level: {state.level.value}")
    print(f"ai: {'off' if state.ai_off else 'on'}")
    for reason in state.reasons:
        print(f"  {reason}")
    print(f"enabled actions: {', '.join(sorted(config.enabled_actions)) or 'none'}")
    print(f"mode: {'dry run' if config.dry_run else 'LIVE'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())