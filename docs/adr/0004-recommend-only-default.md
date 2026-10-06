# ADR 0004: Recommend-Only AI Response by Default

**Date:** 2026-08-31
**Status:** Accepted

## Context
The AI Copilot (M4) analyzes correlated incidents and can propose a
response. Letting it also execute that response autonomously would
remove the human check at exactly the point — a security incident,
possibly a false positive, possibly not — where a wrong automated action
is most costly.

## Decision
By default, the AI Copilot only recommends: it returns reasoning, a
confidence value, and a proposed action, and takes no action itself. A
human operator reviews and explicitly approves before anything executes.
A narrow, explicitly configured whitelist of safe, reversible actions may
be auto-executed later, but nothing is on that list in v1 — every
response in v1 requires operator approval. This is independent of ADR
0003 (which AI provider is used); it governs what any provider's output
is allowed to do.

## Consequences
- No incident response action happens without a human decision in v1 —
  slower than autonomous response, but it matches the threat model's
  explicit non-goal ("fully autonomous AI-driven response without human
  confirmation") and avoids a wrong automated action on a possible false
  positive.
- The AI Copilot's output contract must carry a proposed action as
  structured data (not as a side effect), so the operator has something
  concrete to approve or reject — see `docs/ai-copilot-contract.md`.
- Introducing the auto-execution whitelist later is an explicit,
  separately-reviewed decision, not a default that quietly expands.