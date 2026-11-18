# Deploying brain on AWS

Production has run on AWS ECS Fargate (`us-west-2`, cluster `opsagent`) since 2026-11-12. Source of truth: `docs/tech-spec/aws-hosting.md` in the hub; the infrastructure is Terraform in `opsagent-infra`.

`.github/workflows/deploy-aws.yml` runs after a green `ci` for a push to `main`, or by hand. It assumes the role in the repo variable `AWS_DEPLOY_ROLE_ARN` through GitHub OIDC (no AWS key is stored in GitHub; the role trusts this workflow file on `main` only, `opsagent-infra/deploy.tf`), builds the root `Dockerfile` and `deploy/backup/Dockerfile`, pushes both to ECR under the commit SHA (tags are immutable, `ecr.tf`; an image that is already there is not rebuilt), runs `opsagent-brain db migrate` as a one-off task, then rolls `api`, `worker` and `scheduler` with `deploy/aws/roll.sh`. A failed migration stops the deploy before any service rolls.

The three services share the image and differ in command and settings (`opsagent-infra/ecs.tf`):

| Service | Command | Tasks | Settings |
|---|---|---|---|
| `api` | `opsagent-brain start` (image default) | 1 | load balancer health check `/readyz`; rolling, min 100 / max 200; stop timeout 30 s |
| `worker` | `opsagent-brain start --worker` | 1 | stop timeout 120 s, `WORKER_SHUTDOWN_GRACE_SECS=110` |
| `scheduler` | `opsagent-brain scheduler` | exactly 1 | min 0 / max 100, so a deploy stops the old task before the new one starts |

The scheduler must never overlap itself during a deploy. Migrations are not serialised: SeaORM's migrator takes no lock, so two concurrent `db migrate` runs can race. Hence one migrator (the deploy's one-off task) and `DB_AUTO_MIGRATE` defaulting to false in production. Migrations must stay backward compatible (expand/contract) because `worker` and `scheduler` restart after `api`, and because a rollback (below) puts older code on the newer schema.

## Variables (SSM parameters under `/opsagent/prod/brain`, injected into all three services; `Config::from_env` in `app/src/config.rs` fails boot, naming every missing required one)

The image sets `APP_ENV=production` and `PORT=3000`. `LOCO_ENV` is still read when `APP_ENV` is unset, with a deprecation warning, for one release only; set `APP_ENV`.

| Kind | Variables |
|---|---|
| Sealed | `OPSAGENT_KEK`, `TURNSTILE_SECRET_KEY`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `SLACK_CLIENT_SECRET`, `SLACK_SIGNING_SECRET`, `GITHUB_CLIENT_SECRET`, `RESEND_API_KEY`, `SESSION_SECRET`, `UNSUBSCRIBE_SECRET`, `TRUSTED_PROXY_SECRET`, `JWT_SIGNING_KEY` |
| Plain | `DATABASE_URL`, `REDIS_URL`, `APP_BASE_URL`, `WEB_BASE_URL`, `SLACK_CLIENT_ID`, `MAIL_FROM`, `OPSAGENT_CONNECTORS=aws`, `OPSAGENT_AWS_OUTBOUND_ROLE_ARN`, `OPSAGENT_TEMPLATE_BASE_URL` |

Required today: `DATABASE_URL`, `REDIS_URL`, `APP_BASE_URL`, `WEB_BASE_URL`, `SESSION_SECRET`, `OPSAGENT_KEK`, `OPSAGENT_CONNECTORS`, `SIGNUP_ALLOWED_DOMAINS` (comma-separated email domains; `*` opens sign-up to everyone), `TURNSTILE_SECRET_KEY` (the Cloudflare Turnstile secret; `POST /v1/auth/magic-link`, `/v1/contact` and `/v1/waitlist` verify the request's `turnstile_token` with Cloudflare first and answer 400 `challenge_failed`, or 503 `challenge_unavailable` when Cloudflare cannot answer; outside production an unset secret checks nothing; `TURNSTILE_API_BASE` is a test-only override), and `RESEND_API_KEY` (a loopback `MAILER_SMTP_URL` replaces it). `OPSAGENT_AWS_OUTBOUND_ROLE_ARN` and `OPSAGENT_TEMPLATE_BASE_URL` are optional at boot: while the ARN is unset, creating an AWS connection answers 503 `connector_unavailable`. Plan 2 adds Slack delivery and recipient mail, so `RESEND_API_KEY` is needed at boot by every production process, including one-off CLI commands (`opsagent-brain task ...`, `db migrate`, `scheduler`): without it boot fails with "RESEND_API_KEY is required in production". Set it on all three services and in any shell that runs a task. The `api` service also needs `TRUSTED_PROXY_SECRET` in production and refuses to start without it; `worker` and `scheduler` do not.

Plan 2 variables (placeholders only; real values live in SSM, pushed by `opsagent-infra/scripts/push-env.sh`):

| Variable | Kind | Purpose |
|---|---|---|
| `SLACK_CLIENT_ID` | plain | Slack app client id (OAuth install) |
| `SLACK_CLIENT_SECRET` | sealed | Slack app client secret |
| `MAIL_FROM` | plain | sender for recipient mail and the waitlist confirmation (which also uses `RESEND_API_KEY`; no new variables), default `OpsAgent <info@opsagent.dev>` |
| `SLACK_API_BASE_URL` | plain, optional | default `https://slack.com/api`; override only for tests |

Unsubscribe tokens are HMACs keyed from `UNSUBSCRIBE_SECRET` (sealed, at least 16 bytes), falling back to `SESSION_SECRET` when unset. Set it before the first weekly ships; to switch from the fallback without breaking links already sent, set it equal to the current `SESSION_SECRET`. Rotating `UNSUBSCRIBE_SECRET` invalidates every outstanding unsubscribe link, so do not rotate it; once it is set, `SESSION_SECRET` may rotate freely. `SLACK_SIGNING_SECRET`, Stripe and `JWT_SIGNING_KEY` are listed for later plans and not read yet. Optional: `TRUSTED_PROXY_SECRET` (sealed; behind Cloudflare, set it here and as a Cloudflare Transform Rule that adds the request header `X-Origin-Auth` with the same value, so per-IP rate limits use `CF-Connecting-IP` instead of the Cloudflare edge address; unset or a missing or wrong header keeps the rightmost `X-Forwarded-For`), `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `COOKIE_DOMAIN` (default `opsagent.dev`), `OPSAGENT_KEK_VERSION`, `OPSAGENT_KEK_PREV`, `LOG_LEVEL`. The `api` task definition sets `PORT` and `BINDING`; Terraform owns `DATABASE_URL`, `REDIS_URL` and `OPSAGENT_AWS_OUTBOUND_ROLE_ARN` (`opsagent-infra/data.tf`).

Worker variables (optional; read by `start --worker` and `start --server-and-worker`):

| Variable | Default | Purpose |
|---|---|---|
| `WORKER_CONCURRENCY` | `4` | jobs run at once per worker process |
| `WORKER_SCAN_SLOTS` | `2` | full scans at once per worker (never every slot); an organisation runs one full scan at a time |
| `WORKER_POLL_MS` | `1000` | idle poll interval of the `jobs` table |
| `JOB_LOCK_MAX_AGE_SECS` | `25200` (7 h, above the 6 h scan cap) | a job lock older than this is taken over; the ledger fence rejects the dead writer |
| `WORKER_SHUTDOWN_GRACE_SECS` | `30` | on SIGTERM, time in-flight jobs get to finish; keep below the task stop timeout | Local compose values live in `.env.docker.example`.

Abuse and spend caps (optional):

| Variable | Default | Purpose |
|---|---|---|
| `AI_DAILY_CREDIT_LIMIT` | `10000` (about $100) | credits per UTC day on OpsAgent's model key across all organisations; over it those calls answer `ai_unavailable` and an error is logged once. BYOK is unaffected. |
| `MAGIC_LINK_HOURLY_CAP` | `1000` | sign-in mails per hour across all clients; over it the API still answers 202, sends nothing and logs an error |

## Slack app

Create the app from the hub manifest `docs/ops/slack-app-manifest.json` and follow `docs/ops/slack-app-setup.md` (both in the architecture repo). Bot scopes: `chat:write`, `chat:write.public`, `channels:read`, `groups:read`. Production redirect URL: `https://brain.opsagent.dev/v1/integrations/slack/callback`. Copy the Client ID and Client Secret into `SLACK_CLIENT_ID` and `SLACK_CLIENT_SECRET`. Customers install through the dashboard's Connect Slack button, not from the Slack admin page.

## Post-deploy smoke

After a deploy, run the manual step: the `ci` workflow's `smoke` job via "Run workflow" with `base_url`, or locally `scripts/smoke.sh https://brain.opsagent.dev`. Add `SMOKE_ORG_SLUG`, `SMOKE_CONNECTION_ID`, `SMOKE_ROLE_ARN` and `SMOKE_SESSION_COOKIE` (repository secrets in CI) to also verify the founder's connection. Add `SMOKE_BRIEFING_CONNECTION_ID` with the same `SMOKE_ORG_SLUG` and `SMOKE_SESSION_COOKIE` to also check the briefing preview. Then confirm a scheduler tick in the scheduler logs.

## Backups

Two layers, both in the production account (shortcut noted in `opsagent-infra/buckets.tf`: they survive a lost database, not a lost account):

- **RDS automated backups**, kept 7 days, which is what point-in-time restore uses (`backup_retention_period = 7`, `opsagent-infra/data.tf`). Deletion protection is on and a final snapshot is taken on delete.
- **Nightly logical dump.** An EventBridge Scheduler schedule `opsagent-pg-backup` starts the ECS task `opsagent-backup` at 03:00 UTC (`opsagent-infra/backup.tf`). The task runs `deploy/backup/pg_dump.sh` from the `opsagent-backup` image: `pg_dump` in custom format, uploaded to `s3://opsagent-db-backups-<account id>/postgres/opsagent-<UTC time>.dump`. The bucket is private, versioned and TLS-only; objects expire after 30 days and noncurrent versions after 7 (`buckets.tf`). The task role may only `s3:PutObject` on `postgres/*`; its execution role reads `DATABASE_URL` and no other brain secret. Logs: `/opsagent/prod/backup`, 30 days.

The schedule runs one pinned image, not the latest: `backup_image_tag` in `opsagent-infra` (`backup.tf`, `variables.tf`). Every deploy pushes `opsagent-backup:<sha>`, but a change to `deploy/backup/` reaches the nightly run only after `backup_image_tag` is set to that SHA and Terraform is applied. That ECR repository has no expiry rule, so the pinned image is not deleted (`ecr.tf`).

`pg_dump` cannot dump a server newer than itself, so the image base (`postgres:18-alpine`; RDS runs PostgreSQL 18, `data.tf`) must be bumped with Postgres. A wrong base fails the backup run, not the product.

Who notices a failure:

- The EventBridge rule `opsagent-backup-failed` mails the alarms topic when a backup task stops any way but a clean exit: a failed pull, a crash, a non-zero exit (`opsagent-infra/monitoring.tf`). A run the scheduler cannot start at all is not covered (same file). The rule has not fired yet, so its mail is unconfirmed.
- `.github/workflows/backup-check.yml` runs daily at 09:30 UTC and fails (GitHub emails the repo watchers) when the newest dump under `postgres/` is over 36 hours old or missing. It signs in with GitHub OIDC as the role `opsagent-backup-check` (`s3:ListBucket` on `postgres/*`, nothing else; `buckets.tf`); no AWS key is stored in the repo.

### Database TLS

RDS refuses plaintext (`rds.force_ssl=1`, `data.tf`). Both images carry the AWS RDS CA bundle at `/etc/ssl/rds/global-bundle.pem` (`deploy/backup/rds-global-bundle.pem`, a copy of `https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem` taken 2026-11-14; refresh it when AWS adds a CA the database uses). To verify the server certificate, `DATABASE_URL` ends in `?sslmode=verify-full&sslrootcert=/etc/ssl/rds/global-bundle.pem`. Brain (sqlx) and `pg_dump.sh` both honour it; `pg_dump.sh` accepts those two parameters and stops on any other. Production does not set the suffix yet (`data.tf`). Before it does, every running brain task and the pinned backup image must be builds that contain the bundle, or they fail to connect.

`REDIS_URL` may be `rediss://` (TLS, verified against the public web roots) or `redis://`. Production uses `redis://` until ElastiCache in-transit encryption is turned on (`data.tf`).

## Rollback

1. **A new task that will not start or fails its health check** is handled by ECS: the deployment circuit breaker with rollback is on for every service (`opsagent-infra/ecs.tf`), so the service returns to the previous task definition. The deploy workflow then fails at "Wait for the services to settle" (unconfirmed: not observed in a real failed deploy).
2. **A release that starts but misbehaves**: Actions, `deploy-aws`, "Run workflow" on `main`, with `sha` set to the full 40-character SHA of the commit to go back to. The SHA must be a commit on `main`. If `opsagent-brain:<sha>` is still in ECR the run skips the build and only rolls the three services; otherwise it rebuilds that commit first. ECR keeps the last 90 manifests of `opsagent-brain`, about 30 releases (`ecr.tf`). The run uses that commit's `deploy/aws/roll.sh`, so the oldest SHA that can be deployed this way is the first one that has the script.
3. **The schema is not rolled back.** A run with `sha` does not migrate: migrations only go forward, and `db migrate` from an older binary fails on applied migrations it does not know. The older code runs against the newer schema, which is safe one release back as long as migrations follow expand/contract. Going back across a contract step (a dropped column or table the old code reads) needs a new forward migration or a database restore, not this.
4. To go forward again, merge the fix to `main` (the normal deploy migrates), or run `deploy-aws` by hand with `sha` empty to deploy the head of `main`.

A `sha` run does not change which image the nightly backup runs (`backup_image_tag`, above). No rollback through this input has been run yet.

## Restore

No restore of a dump produced on AWS and no point-in-time restore has been drilled yet; the one recorded restore into RDS is the cutover load of 2026-11-12 (hub `DECISIONS.md`). Both paths need the admin credentials from the hub's `.secrets/aws.prod.env`: the deploy and backup roles cannot read dumps or touch RDS.

### Point in time (RDS, last 7 days)

RDS restores into a **new** instance; the running one is not changed.

1. `aws rds describe-db-instances --db-instance-identifier opsagent --query 'DBInstances[0].LatestRestorableTime'` shows how recent a restore can be.
2. `aws rds restore-db-instance-to-point-in-time --source-db-instance-identifier opsagent --target-db-instance-identifier opsagent-restore-<date> --restore-time <UTC timestamp>` (or `--use-latest-restorable-time`), with `--db-subnet-group-name opsagent`, the data security group (`aws_security_group.data`, `opsagent-infra/security.tf`), the `opsagent-pg18-*` parameter group and `--no-publicly-accessible`. Without those the copy lands in the default VPC settings (unconfirmed which of them the CLI inherits from the source).
3. With the data security group the copy is reachable from brain's tasks only, not from a laptop. Check it with `opsagent-brain db status` (every migration applied) from a one-off ECS task whose `DATABASE_URL` points at the copy. Unconfirmed how best to pass that URL: the task definitions inject `DATABASE_URL` as a secret, and the cutover restore of 2026-11-12 used a one-off task whose definition is not in this repo.
4. Pointing production at the copy is unconfirmed and has not been drilled: `DATABASE_URL` is a Terraform-owned SSM parameter built from `aws_db_instance.main` (`data.tf`), so a hand edit is overwritten by the next apply. Decide between importing the restored instance into Terraform and copying the data back before doing this for real.
5. Delete the copy when done; it is outside Terraform and bills until deleted.

### A nightly dump into a throwaway database (monthly check)

1. Download the latest `postgres/*.dump` from `opsagent-db-backups-<account id>`.
2. Create a scratch Postgres 18 (local `docker compose up -d postgres`, new database `restore_check`).
3. `pg_restore --no-owner --dbname=<scratch url> <file>.dump` finishes without errors.
4. `DATABASE_URL=<scratch url> opsagent-brain db status`: all migrations applied.
5. `select count(*)` on `organisations` and `findings`: counts are plausible against production.
6. Record the date and result in the hub's `DECISIONS.md`; drop the scratch database. Last recorded test: 2026-11-05, against a dump from the old Railway database; next due 2026-12-05 (hub `DECISIONS.md`).

## MCP server (Plan 4)

No new variables. `APP_BASE_URL` must be exactly `https://brain.opsagent.dev` in production: the OAuth issuer, the MCP resource (`{APP_BASE_URL}/mcp`) and the MCP allowed host all derive from it, and boot fails if it is not an absolute URL. `SESSION_SECRET` also keys the consent browser-binding cookie. After deploy, `scripts/smoke.sh https://brain.opsagent.dev` checks MCP discovery and the 401 challenge.

Consent works only on the custom domains (opsagent.dev and brain.opsagent.dev are same-site).
