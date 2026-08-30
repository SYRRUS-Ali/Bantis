# Bantis

Bantis is a self-hosted, open-source security platform that combines automated attack detection, AI-assisted incident response, and supply chain defense simulation — all running entirely on your own infrastructure.

> 🚧 Early development. Architecture docs are in `docs/`.

## Scope (v1)

Bantis v1 focuses on **supply chain attacks** against a CI/CD pipeline and its dependencies, with AI-assisted analysis and human-approved response. See [`docs/threat-model.md`](docs/threat-model.md) for what's explicitly in and out of scope, and [`docs/mitre-mapping.md`](docs/mitre-mapping.md) for the attack techniques covered.

## Design principles

- Fully self-hosted, no cloud dependency ([ADR 0001](docs/adr/0001-self-hosted-only.md))
- Docker Compose primary, Helm advanced, no Terraform ([ADR 0002](docs/adr/0002-no-terraform-compose-primary.md))
- Human-in-the-loop by default; AI recommends, operator approves ([ADR 0004](docs/adr/0004-recommend-only-default.md))

## License

MIT