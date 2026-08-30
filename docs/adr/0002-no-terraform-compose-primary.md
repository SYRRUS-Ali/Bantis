# ADR 0002: Docker Compose as Primary Deployment, No Terraform

**Date:** 2026-08-31
**Status:** Accepted

## Context
Bantis needs to be easy to deploy for a single operator on a single
machine, while still supporting more advanced Kubernetes-based deployments
for users who want them.

## Decision
Docker Compose is the primary, supported deployment method for v1. A Helm
chart is offered as an advanced option for Kubernetes users. Terraform (or
any infrastructure-as-code cloud provisioning tool) is explicitly out of
scope, since Bantis does not provision cloud infrastructure.

## Consequences
- Lower barrier to entry: most users can get started with `docker compose up`.
- Advanced users retain a path to Kubernetes via Helm without it being a
  requirement.
- No cloud-provisioning code to maintain or keep secure.