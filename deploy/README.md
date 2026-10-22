# Deploying brain on Railway

Source of truth: `docs/tech-spec/deployment.md` in the architecture repo. Railway builds the root `Dockerfile` and deploys on push to `main`; `railway.json` sets the pre-deploy migration (`opsagent-brain db migrate`), the `/readyz` healthcheck and the restart policy. The three services below share that image and differ only in start command and variables. `railway.json` applies to all three; the migration is idempotent, but migrations must stay backward compatible (expand/contract) because `worker` and `scheduler` restart after `api`.

| Service | Start command | Replicas | Extra variables |
|---|---|---|---|
| `api` | `opsagent-brain start` (image default) | 1 | none (default overlap) |
| `worker` | `opsagent-brain start --worker` | 1..N | `DRAINING_SECONDS=120` |
| `scheduler` | `opsagent-brain scheduler` | exactly 1 | `RAILWAY_DEPLOYMENT_OVERLAP_SECONDS=0`, `DRAINING_SECONDS=30` |

The scheduler must never overlap itself during a deploy, hence overlap 0 and one replica. `worker` and `scheduler` have no HTTP server, so turn the healthcheck off for them in the Railway service settings (override of `railway.json`).

## Variables (set on all three services; `app/config/production.yaml` fails boot if a required one is missing)

| Kind | Variables |
|---|---|
| Sealed | `OPSAGENT_KEK`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `SLACK_CLIENT_SECRET`, `SLACK_SIGNING_SECRET`, `GITHUB_CLIENT_SECRET`, `RESEND_API_KEY`, `SESSION_SECRET`, `JWT_SIGNING_KEY` |
| Plain | `DATABASE_URL`, `REDIS_URL`, `APP_BASE_URL`, `WEB_BASE_URL`, `OPSAGENT_CONNECTORS=aws`, `OPSAGENT_AWS_OUTBOUND_ROLE_ARN`, `OPSAGENT_TEMPLATE_BASE_URL` |

Required today: `DATABASE_URL`, `REDIS_URL`, `APP_BASE_URL`, `WEB_BASE_URL`, `SESSION_SECRET`, `OPSAGENT_KEK`, `OPSAGENT_CONNECTORS`, `OPSAGENT_AWS_OUTBOUND_ROLE_ARN`, `OPSAGENT_TEMPLATE_BASE_URL`, and `RESEND_API_KEY` (api boot; a loopback `MAILER_SMTP_URL` replaces it). The Stripe, Slack and `JWT_SIGNING_KEY` variables are listed for later plans and not read yet. Optional: `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `COOKIE_DOMAIN` (default `opsagent.dev`), `OPSAGENT_KEK_VERSION`, `OPSAGENT_KEK_PREV`, `MAIL_FROM`, `LOG_LEVEL`. Railway sets `PORT`. Local compose values live in `.env.docker.example`.

## Post-deploy smoke

After a deploy (Railway deploys itself on push to `main`), run the manual step: the `ci` workflow's `smoke` job via "Run workflow" with `base_url`, or locally `scripts/smoke.sh https://brain.opsagent.dev`. Add `SMOKE_ORG_ID`, `SMOKE_CONNECTION_ID` and `SMOKE_SESSION_COOKIE` (repository secrets in CI) to also verify the founder's connection. Then confirm a scheduler tick in the scheduler logs.

## Backups

PITR is on for the Railway Postgres service. A fifth service `pg-backup` runs `deploy/backup/pg_dump.sh` nightly: a Railway cron service (cron schedule `0 3 * * *`) whose image has `postgresql-client` and `awscli`, with variables `DATABASE_URL`, `BACKUP_BUCKET`, `BACKUP_ENDPOINT_URL` (R2 endpoint; omit for S3), `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (sealed). Set a 30-day expiry lifecycle rule on the bucket's `postgres/` prefix.

### Monthly restore test checklist

1. Download the latest `postgres/*.dump` from the bucket.
2. Create a scratch Postgres (local `docker compose up -d postgres`, new database `restore_check`).
3. `pg_restore --no-owner --dbname=<scratch url> <file>.dump` finishes without errors.
4. `DATABASE_URL=<scratch url> opsagent-brain db status`: all migrations applied.
5. `select count(*)` on `organisations` and `findings`: counts are plausible against production.
6. Record the date and result in the runbook; drop the scratch database.
