# Operations

## Adding a shard

New yearly shards appear in `ctlog.json` around November. The scheduled job
then fails with `ALERT log list: log not in logs.json` until a maintainer adds
the shard to `logs.json` by hand, copying `url`, `key` and `log_id` from
`loglist/ctlog.json` and writing `key_source`. Run
`go run ./cmd/ructmirror sync -only <operator>/<shard>` once locally, then
commit `logs.json` together with the new `data/` directory.

A shard whose host disappears should be marked `"disabled": true` with a
`note`; its data stays in the repository.

## Retiring data

The repository stays small enough for GitHub for years, but if it ever grows
past a gigabyte, move whole `data/<operator>/<shard>/` directories of closed
shards into GitHub Releases or a separate archive repository. Never rewrite
history; the value of the mirror is that its history is boring.

## Maintainer identity

Every commit is authored by `ru-ct-mirror <ru-ct-mirror@proton.me>` with a
UTC timestamp; the workflow sets that identity itself. For local pushes:

```
git config user.name ru-ct-mirror
git config user.email ru-ct-mirror@proton.me
TZ=UTC git commit ...
```

Pushes from GitHub Actions are attributed to `github-actions[bot]`. A push
from a personal account is recorded publicly in the repository's Activity
view and the Events API, so use a dedicated machine account with its own SSH
key (`IdentitiesOnly yes` in `~/.ssh/config`) for any manual push.

## Notifications without GitHub e-mail

GitHub refuses alias-style e-mail domains, so the maintainer's notifications
go through [healthchecks.io](https://healthchecks.io) instead. Every run
pings a check with its start, its exit status and a log excerpt; a run that
never happens is noticed as well.

1. Create a check. Schedule: cron `23 */6 * * *`, timezone UTC, grace time
   30 minutes. Attach whatever notification channels you like (e-mail to any
   address, Telegram, Signal, ...). Enable "notify on start" if you want the
   duration tracked.
2. Copy the ping URL (`https://hc-ping.com/<uuid>`) into the repository as
   the `HC_PING_URL` secret (Settings → Secrets and variables → Actions).
3. That is all. The workflow reports `/start` at the beginning and
   `/<exit status>` at the end: `0` for a clean run, `1` for a sync error
   (a log was unreachable), `2` for a verification failure, `3` when a step
   never produced a status because the job itself broke, `4` when everything
   verified but the commit could not be pushed. The request body,
   visible in the check's log on healthchecks.io, holds the run URL and the
   interesting lines of the sync and verify output.

Configure healthchecks to alert on failed pings as well as on missed ones;
then a verification failure, an unreachable log, a broken runner and a
disabled schedule all reach you the same way, and the GitHub issue stays as
the public record.

## Two kinds of issues

- **Verification failure <date>**: a log or the log list failed a
  cryptographic check (`ructmirror` exited 2, or offline `verify` failed).
  Evidence is committed under `alerts/`. This is the one that matters.
- **Sync error <date>**: an operational problem, typically a log that could
  not be reached or returned garbage (`ructmirror` exited 1). Nothing was
  verified wrong, but the mirror is blind until it clears. Persisting for more
  than a day deserves a look: a log that went away is itself a finding.

## Reading a verification failure

`data/<operator>/<shard>/alerts/<time>-<kind>.json` holds everything the run
saw. Kinds:

- `bad-sth-signature`: the STH does not verify with the key in `logs.json`.
  Either the log rotated its key silently or the response was tampered with in
  transit.
- `tree-shrunk`: the log reports a smaller tree than we already verified.
- `same-size-different-root`: same tree size, different root. A split view.
- `root-mismatch`: the entries the log served do not hash to the root it
  signed. The served chunk is kept next to the alert as evidence.
- `inconsistent`: the log's consistency proof between the previous tree and
  the new one does not verify.

In every case `state.json` keeps the last verified tree and the job exits
non-zero after committing the evidence.
