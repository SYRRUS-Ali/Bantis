from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_EVAL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_EVAL_DIR.parent))

from converter import build_copilot_request  # noqa: E402
from prompts import ANALYSIS_PROMPTS, CURRENT_ANALYSIS_PROMPT  # noqa: E402
from providers.base import ProviderUnavailableError  # noqa: E402

DEFAULT_FIXTURE = _EVAL_DIR / "sprint3_incidents.json"


class ProviderAuthError(RuntimeError):
    """The API rejected the key. Every further call would fail the same way,
    so the run stops instead of writing a report full of failures.
    """


class _FailFastClient:
    """Wraps the Anthropic client so an authentication failure escapes the
    provider (which otherwise records it as an ordinary analysis_failed).
    """

    def __init__(self, client) -> None:
        self._client = client
        self.messages = self

    def create(self, **kwargs):
        import anthropic

        try:
            return self._client.messages.create(**kwargs)
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as exc:
            raise ProviderAuthError(
                f"the API rejected ANTHROPIC_API_KEY (HTTP {exc.status_code}); check the key and rerun"
            ) from None

RUBRIC = [
    ("Reads outcomes correctly", "status \"failure\" = attack blocked, \"success\" = got through; doesn't misread exit codes"),
    ("Grounded in the evidence", "names the scenario/event behind each claim; states nothing the data doesn't support"),
    ("Handles the simulation correctly", "says what it shows about the defenses; doesn't treat it as a live breach, doesn't dismiss a real gap"),
    ("Action fits", "the proposed action matches the definitions and the outcome"),
    ("Calibrated", "its own confidence is justified, says what's uncertain, doesn't just copy the rule's"),
    ("Useful to an operator", "concise, specific, clear next step"),
]


def load_requests(fixture: Path):
    data = json.loads(fixture.read_text())
    return [build_copilot_request(item["incident"], item["events"]) for item in data["incidents"]]


def dry_run(requests, versions) -> None:
    for version in versions:
        prompt = ANALYSIS_PROMPTS[version]
        print(f"{'=' * 30} prompt {version}: system {'=' * 30}\n{prompt.system}\n")
        for request in requests:
            print(f"{'-' * 20} prompt {version}: user message, {request.incident.pattern} {'-' * 20}")
            print(prompt.render(request) + "\n")


def _score_table(versions) -> list[str]:
    header = "| Criterion | What good looks like | " + " | ".join(f"{v} (1-3)" for v in versions) + " |"
    rule = "|---|---|" + "---|" * len(versions)
    rows = [f"| {name} | {meaning} | " + " | ".join(" " for _ in versions) + " |" for name, meaning in RUBRIC]
    return [header, rule, *rows]


def evaluate(requests, versions, model: str) -> str:
    import anthropic

    from providers.claude import ClaudeProvider

    client = _FailFastClient(anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"]))
    providers = {v: ClaudeProvider(model=model, client=client, prompt=ANALYSIS_PROMPTS[v]) for v in versions}
    now = datetime.now(timezone.utc)
    failed = 0
    lines = [
        f"# Copilot prompt evaluation -- {now.strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"Model `{model}`; prompts {', '.join(versions)}; {len(requests)} Sprint 3 incidents "
        "(`eval/sprint3_incidents.json`). Score each criterion 1 (poor) to 3 (good) and note why.",
        "",
    ]
    for request in requests:
        incident = request.incident
        lines += [
            f"## {incident.pattern}",
            "",
            f"Rule severity `{incident.severity}`, rule confidence `{incident.confidence}`. "
            f"Summary: {incident.summary}",
            "",
            "Evidence: " + "; ".join(
                f"{e.scenario or e.event_type} ({e.status or 'no status'})" for e in request.evidence_timeline
            ),
            "",
        ]
        for version in versions:
            trace = providers[version].analyze_traced(request)
            response = trace.response
            failed += response.proposed_action.type == "analysis_failed"
            tokens = sum((a.input_tokens or 0) + (a.output_tokens or 0) for a in trace.attempts)
            lines += [
                f"### Prompt {version}",
                "",
                f"- **Action:** `{response.proposed_action.type}` -- {response.proposed_action.description}",
                f"- **AI confidence:** {response.confidence}",
                f"- **Attempts:** {len(trace.attempts)} ({tokens:,} tokens)",
                "",
                *[f"> {line}" for line in response.reasoning.splitlines() or [""]],
                "",
            ]
        lines += ["### Scores", "", *_score_table(versions), "", "Notes:", "", ""]
    if failed:
        total = len(requests) * len(versions)
        lines[3:3] = [f"**{failed} of {total} analyses failed and have nothing to score.**", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare Copilot analysis prompts on real Sprint 3 incidents.")
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument(
        "--versions", nargs="+", default=sorted(ANALYSIS_PROMPTS), choices=sorted(ANALYSIS_PROMPTS),
        help=f"Prompt versions to compare (default: all; current is {CURRENT_ANALYSIS_PROMPT.version}).",
    )
    parser.add_argument("--model", default=None, help="Model to evaluate with (default: the provider's default).")
    parser.add_argument("--dry-run", action="store_true", help="Print exactly what would be sent; make no calls.")
    args = parser.parse_args(argv)

    requests = load_requests(args.fixture)
    if args.dry_run:
        dry_run(requests, args.versions)
        return 0
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY is not set; use --dry-run to see the prompts without calling the API.", file=sys.stderr)
        return 2

    from providers.claude import DEFAULT_MODEL

    model = args.model or DEFAULT_MODEL
    print(f"Running {len(requests)} incidents x {len(args.versions)} prompt versions "
          f"(up to {len(requests) * len(args.versions) * 3} model calls) with {model}...", file=sys.stderr)
    try:
        report = evaluate(requests, args.versions, model)
    except (ProviderAuthError, ProviderUnavailableError) as exc:
        print(f"stopped: {exc}. No report written.", file=sys.stderr)
        return 3
    out_dir = _EVAL_DIR / "results"
    out_dir.mkdir(exist_ok=True)
    out = out_dir / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{'-'.join(args.versions)}.md"
    out.write_text(report)
    print(f"wrote {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())