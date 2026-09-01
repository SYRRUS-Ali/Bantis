# Range

This is the target environment for Bantis's supply-chain attack scenarios —
a FastAPI + PostgreSQL + Redis + Nginx stack reused from
[compose-multiservice-app](https://github.com/SYRRUS-Ali/compose-multiservice-app),
instrumented and intentionally exposed as the attack surface that later
milestones (Attack Simulation, Detection Engine) operate against.

This is not a standalone project — see the root [README](../README.md) for
the full Bantis scope.