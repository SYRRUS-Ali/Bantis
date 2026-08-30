# ADR 0003: Single AI Provider (Claude) for v1, Pluggable Abstraction Later

**Date:** 2026-08-31
**Status:** Accepted

## Context
The AI Copilot needs to analyze correlated incidents and produce reasoning
and recommendations. Supporting many providers from day one adds
integration complexity before the core reasoning pipeline is proven.

## Decision
v1 integrates a single AI provider, Claude, accessed with the operator's
own API key. The integration is built behind an internal abstraction so
that additional providers (OpenAI, local models via Ollama) can be added
later without redesigning the copilot pipeline.

## Consequences
- Faster path to a working, well-tuned AI reasoning pipeline in v1.
- Some rework will be needed later to fully generalize the abstraction, but
  the interface is designed with that in mind from the start.
- Operators without a Claude API key cannot use the AI Copilot in v1; this
  is a known limitation to document.