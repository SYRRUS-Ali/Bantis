# ADR 0001: Fully Self-Hosted, No Cloud Dependency

**Date:** 2026-08-31
**Status:** Accepted

## Context
Bantis is meant to be installed and run entirely by the operator, without
requiring any third-party cloud service or SaaS dependency for its core
function.

## Decision
Bantis will be fully self-hosted. All components (range, detection engine,
AI copilot orchestration, response controller, dashboard) run on
infrastructure the operator controls. No component requires a hosted
backend operated by the Bantis project itself.

## Consequences
- Operators get full data privacy and control; no data leaves their
  infrastructure except explicit AI provider API calls they configure
  themselves.
- Installation and updates are the operator's responsibility (no managed
  hosting option in v1).
- Simplifies the trust model: Bantis itself is never a third party with
  access to the operator's data.