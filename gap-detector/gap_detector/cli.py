from __future__ import annotations

import argparse
import http.client
import json
import math
import os
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError

from .client import IncidentClient
from .core import compare, read_history, utc
from .review_queue import ReviewQueue, queue_path
from .suggester import suggest_rules


def seconds(value: str) -> float:
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise argparse.ArgumentTypeError("seconds must be finite and nonnegative")
    return result


def write_report(path: Path, report: dict) -> None:
    # Replace atomically, keeping the previous complete report on any failure.
    path.parent.mkdir(parents=True, exist_ok=True)
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".gap-report-", delete=False) as stream:
            name = stream.name
            json.dump(report, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if name is not None and os.path.exists(name):
            os.unlink(name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare attack-sim history with M3 incidents.")
    parser.add_argument("--history", required=True, type=Path, help="Saved attack-sim stdout log")
    parser.add_argument("--detection-url", default="http://127.0.0.1:8000")
    parser.add_argument("--output", required=True, type=Path, help="Atomic JSON report path")
    parser.add_argument("--review-queue", type=Path, help="Persistent SQLite review queue (default: beside output)")
    timing = parser.add_mutually_exclusive_group()
    timing.add_argument("--wait-seconds", type=seconds, default=330,
                        help="Per-run emission-to-deadline allowance (default: 330)")
    timing.add_argument("--deadline", type=utc, help="Fixed exercise deadline, ISO 8601 with timezone")
    parser.add_argument("--interval", type=seconds, default=0,
                        help="Polling interval; 0 checks once (default)")
    parser.add_argument("--timeout", type=seconds, default=5)
    args = parser.parse_args(argv)
    queue = queue_path(args.output, args.review_queue)
    if len({args.history.resolve(), args.output.resolve(), queue.resolve()}) != 3:
        parser.error("history, output, and review queue must be different files")
    try:
        client = IncidentClient(args.detection_url, timeout=args.timeout)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        while True:
            stage = "history"
            try:
                events = read_history(args.history)
                stage = "incidents"
                incidents = client.incidents()
                stage = "comparison"
                report = compare(events, incidents, now=datetime.now(timezone.utc),
                                 wait_seconds=args.wait_seconds, deadline=args.deadline)
                report["source"] = {"history": str(args.history.resolve()),
                                    "detection_url": args.detection_url,
                                    "wait_seconds": None if args.deadline else args.wait_seconds,
                                    "deadline": args.deadline.isoformat() if args.deadline else None}
                stage = "suggestions"
                report["rule_suggestions"] = suggest_rules(report)
                stage = "review_queue"
                ReviewQueue(queue).enqueue(report["rule_suggestions"])
                stage = "report"
                write_report(args.output, report)
                print(json.dumps({"status": "ok", "observed_at": report["observed_at"],
                                  "counts": report["counts"]}), flush=True)
                if args.interval == 0:
                    return 1 if report["counts"]["gap"] or report["counts"]["late_detection"] else 0
            except (OSError, ValueError, URLError, http.client.HTTPException, OverflowError, sqlite3.Error) as exc:
                # Never echo raw event or response content (it may contain secrets).
                print(json.dumps({"status": "error", "stage": stage, "error_type": type(exc).__name__,
                                  "message": "Check incomplete; previous report retained."}),
                      file=sys.stderr, flush=True)
                if args.interval == 0:
                    return 2
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0