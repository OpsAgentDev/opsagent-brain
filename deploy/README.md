# Deploying brain on Railway

Source of truth: `docs/tech-spec/deployment.md` in the architecture repo. Railway builds the root `Dockerfile` and deploys on push to `main`; `railway.json` sets the pre-deploy migration (`opsagent-brain db migrate`), the `/readyz` healthcheck and the restart policy. The three services below share that image and differ only in start command and variables. Only `api` may run the pre-deploy command: in the Railway settings of `worker` and `scheduler`, clear the pre-deploy command (and the healthcheck) so they do not inherit `railway.json`'s. Migrations are not serialised: SeaORM's migrator takes no lock, so two concurrent `db migrate` runs can race. Hence one migrator (`api` pre-deploy) and `DB_AUTO_MIGRATE` defaulting to false in production. Migrations must stay backward compatible (expand/contract) because `worker` and `scheduler` restart after `api`.

| Service | Start command | Replicas | Extra variables |
|---|---|---|---|
| `api` | `opsagent-brain start` (image default) | 1 | none (default overlap) |
| `worker` | `opsagent-brain start --worker` | 1..N | `DRAINING_SECONDS=120` |
| `scheduler` | `opsagent-brain scheduler` | exactly 1 | `RAILWAY_DEPLOYMENT_OVERLAP_SECONDS=0`, `DRAINING_SECONDS=30` |

The scheduler must never overlap itself during a deploy, hence overlap 0 and one replica.

## Variables (set on all three services; `Config::from_env` in `app/src/config.rs` fails boot, naming every missing required one)

The image sets `APP_ENV=production` and `PORT=3000`. `LOCO_ENV` is still read when `APP_ENV` is unset, with a deprecation warning, for one release only; set `APP_ENV`.

| Kind | Variables |
|---|---|
| Sealed | `OPSAGENT_KEK`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `SLACK_CLIENT_SECRET`, `SLACK_SIGNING_SECRET`, `GITHUB_CLIENT_SECRET`, `RESEND_API_KEY`, `SESSION_SECRET`, `UNSUBSCRIBE_SECRET`, `JWT_SIGNING_KEY` |
| Plain | `DATABASE_URL`, `REDIS_URL`, `APP_BASE_URL`, `WEB_BASE_URL`, `SLACK_CLIENT_ID`, `MAIL_FROM`, `OPSAGENT_CONNECTORS=aws`, `OPSAGENT_AWS_OUTBOUND_ROLE_ARN`, `OPSAGENT_TEMPLATE_BASE_URL` |

Required today: `DATABASE_URL`, `REDIS_URL`, `APP_BASE_URL`, `WEB_BASE_URL`, `SESSION_SECRET`, `OPSAGENT_KEK`, `OPSAGENT_CONNECTORS`, and `RESEND_API_KEY` (a loopback `MAILER_SMTP_URL` replaces it). `OPSAGENT_AWS_OUTBOUND_ROLE_ARN` and `OPSAGENT_TEMPLATE_BASE_URL` are optional at boot: while the ARN is unset, creating an AWS connection answers 503 `connector_unavailable`. Plan 2 adds Slack delivery and recipient mail, so `RESEND_API_KEY` is needed at boot by every production process, including one-off CLI commands (`opsagent-brain task ...`, `db migrate`, `scheduler`): without it boot fails with "RESEND_API_KEY is required in production". Set it on all three services and in any shell that runs a task.

Plan 2 variables (placeholders only; real values live in Railway):

| Variable | Kind | Purpose |
|---|---|---|
| `SLACK_CLIENT_ID` | plain | Slack app client id (OAuth install) |
| `SLACK_CLIENT_SECRET` | sealed | Slack app client secret |
| `MAIL_FROM` | plain | sender for recipient mail and the waitlist confirmation (which also uses `RESEND_API_KEY`; no new variables), default `OpsAgent <info@opsagent.dev>` |
| `SLACK_API_BASE_URL` | plain, optional | default `https://slack.com/api`; override only for tests |

Unsubscribe tokens are HMACs keyed from `UNSUBSCRIBE_SECRET` (sealed, at least 16 bytes), falling back to `SESSION_SECRET` when unset. Set it before the first weekly ships; to switch from the fallback without breaking links already sent, set it equal to the current `SESSION_SECRET`. Rotating `UNSUBSCRIBE_SECRET` invalidates every outstanding unsubscribe link, so do not rotate it; once it is set, `SESSION_SECRET` may rotate freely. `SLACK_SIGNING_SECRET`, Stripe and `JWT_SIGNING_KEY` are listed for later plans and not read yet. Optional: `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `COOKIE_DOMAIN` (default `opsagent.dev`), `OPSAGENT_KEK_VERSION`, `OPSAGENT_KEK_PREV`, `LOG_LEVEL`. Railway sets `PORT`.

Worker variables (optional; read by `start --worker` and `start --server-and-worker`):

| Variable | Default | Purpose |
|---|---|---|
| `WORKER_CONCURRENCY` | `4` | jobs run at once per worker process |
| `WORKER_POLL_MS` | `1000` | idle poll interval of the `jobs` table |
| `JOB_LOCK_MAX_AGE_SECS` | `25200` (7 h, above the 6 h scan cap) | a job lock older than this is taken over; the ledger fence rejects the dead writer |
| `WORKER_SHUTDOWN_GRACE_SECS` | `30` | on SIGTERM, time in-flight jobs get to finish; keep below `DRAINING_SECONDS` | Local compose values live in `.env.docker.example`.

## Slack app

Create the app from the hub manifest `docs/ops/slack-app-manifest.json` and follow `docs/ops/slack-app-setup.md` (both in the architecture repo). Bot scopes: `chat:write`, `chat:write.public`, `channels:read`, `groups:read`. Production redirect URL: `https://brain.opsagent.dev/v1/integrations/slack/callback`. Copy the Client ID and Client Secret into `SLACK_CLIENT_ID` and `SLACK_CLIENT_SECRET`. Customers install through the dashboard's Connect Slack button, not from the Slack admin page.

## Post-deploy smoke

After a deploy (Railway deploys itself on push to `main`), run the manual step: the `ci` workflow's `smoke` job via "Run workflow" with `base_url`, or locally `scripts/smoke.sh https://brain.opsagent.dev`. Add `SMOKE_ORG_SLUG`, `SMOKE_CONNECTION_ID`, `SMOKE_ROLE_ARN` and `SMOKE_SESSION_COOKIE` (repository secrets in CI) to also verify the founder's connection. Add `SMOKE_BRIEFING_CONNECTION_ID` with the same `SMOKE_ORG_SLUG` and `SMOKE_SESSION_COOKIE` to also check the briefing preview. Then confirm a scheduler tick in the scheduler logs.

## Backups

PITR is on for the Railway Postgres service. A fifth service `pg-backup` runs `deploy/backup/pg_dump.sh` nightly: a Railway cron service (cron schedule `0 3 * * *`) built from `deploy/backup/Dockerfile` (build context: repo root; the image runs `pg_dump.sh`), with variables `DATABASE_URL`, `BACKUP_BUCKET`, `BACKUP_ENDPOINT_URL` (R2 endpoint; omit for S3), `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (sealed). Set a 30-day expiry lifecycle rule on the bucket's `postgres/` prefix.

### Monthly restore test checklist

1. Download the latest `postgres/*.dump` from the bucket.
2. Create a scratch Postgres (local `docker compose up -d postgres`, new database `restore_check`).
3. `pg_restore --no-owner --dbname=<scratch url> <file>.dump` finishes without errors.
4. `DATABASE_URL=<scratch url> opsagent-brain db status`: all migrations applied.
5. `select count(*)` on `organisations` and `findings`: counts are plausible against production.
6. Record the date and result in the runbook; drop the scratch database.

## MCP server (Plan 4)

No new variables. `APP_BASE_URL` must be exactly `https://brain.opsagent.dev` in production: the OAuth issuer, the MCP resource (`{APP_BASE_URL}/mcp`) and the MCP allowed host all derive from it, and boot fails if it is not an absolute URL. `SESSION_SECRET` also keys the consent browser-binding cookie. After deploy, `scripts/smoke.sh https://brain.opsagent.dev` checks MCP discovery and the 401 challenge.

Consent works only on the custom domains (opsagent.dev and brain.opsagent.dev are same-site); on *.up.railway.app previews the SameSite=Lax consent cookie is not sent and consent returns 403.
