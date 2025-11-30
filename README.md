# noclickops-api

Minimal Go API for managing tenants, users, and scanner configs.

## Environment

- `DATABASE_URL` – target DB (e.g. `postgres://user:pass@localhost:5432/noclickops?sslmode=disable`)
- `ADMIN_DATABASE_URL` – optional superuser DSN used to create the database (default derives from `DATABASE_URL` pointing at `postgres` DB).
- `JWT_SECRET` – HMAC secret for issuing login tokens.

## Run

```bash
cd noclickops-api
go run ./cmd/api
```

On startup it:
1) Creates the `noclickops` database if missing.
2) Runs migrations for tenants, users, scanners.

Seed an initial user:
```bash
psql "$DATABASE_URL" -f seed.sql
# user: admin@example.com
# pass: Password123!
```

## Frontend

A minimal UI is served from `./web` (home/login/dashboard). Open http://localhost:8080/ in the browser. Login uses the `/login` endpoint and displays your tenant and scanners (`/me`, `/scanners` GET).

## Endpoints

- `POST /login` → `{email, password}` → `{token}`
- `POST /tenants` (auth) → `{name}`
- `GET /me` (auth) → user + tenant info
- `GET /scanners` (auth) → list scanners for tenant
- `POST /scanners` (auth) → `{name, cloud_provider: aws|gcp|azure, config: {...}}`

`Authorization: Bearer <token>` is required for tenant/scanner creation. Users and scanners are scoped to the tenant in the JWT claims.
