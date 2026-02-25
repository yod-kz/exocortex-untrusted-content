# tool-untrusted-content (Kamiwaza Tool)

Kamiwaza extension packaging for the untrusted content pipeline service.

## Local Development

```bash
cd tools/tool-untrusted-content
docker compose up --build
```

Service endpoint: `http://localhost:8787`

## API

- `GET /health`
- `POST /v1/pipeline`
- `POST /v1/honeypot/trigger`

## Deploy (App Garden / Tool Shed)

This directory includes:

- `kamiwaza.json`
- `docker-compose.yml` (local build)
- `docker-compose.appgarden.yml` (registry/deploy)

Use your standard extensions workflow (`make sync-compose`, `make build-registry`, `make kamiwaza-push`, etc.) from a Kamiwaza extensions repo.
