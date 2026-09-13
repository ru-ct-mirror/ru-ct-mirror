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
