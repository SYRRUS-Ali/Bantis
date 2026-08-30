# ADR 0005: Single Attack Layer (Supply Chain) for v1

**Date:** 2026-08-31
**Status:** Accepted

## Context
Building detection and simulation for both a supply-chain layer and a
network/host layer at once would split effort across two different threat
models before either is mature.

## Decision
v1 focuses exclusively on the supply-chain attack layer (see
`docs/threat-model.md` and `docs/mitre-mapping.md`). A network/host attack
layer is deferred to a post-v1.0.0 milestone (M7).

## Consequences
- Allows the range, detection rules, and AI reasoning to be developed and
  tuned deeply for one coherent threat model first.
- v1.0.0 will not detect network-layer attacks; this is a known,
  intentional limitation to state clearly in the README.
- Reuses lessons learned from the supply-chain layer when the second layer
  is eventually added.