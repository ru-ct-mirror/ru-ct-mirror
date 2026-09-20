# Operations

## Adding a shard

New yearly shards appear in `ctlog.json` around November. The scheduled job
then fails with `ALERT log list: log not in logs.json` until a maintainer adds
the shard to `logs.json` by hand, copying `url`, `key`, `log_id` and `mmd`
from `loglist/ctlog.json` and writing `key_source`. Run
`go run ./cmd/ructmirror sync -only <operator>/<shard>` once locally, then
commit `logs.json` together with the new `data/` directory.

A shard whose host disappears should be marked `"disabled": true` with a
`note`; its data stays in the repository.

## The runner image

Both jobs pin `runs-on: ubuntu-26.04` rather than `ubuntu-latest`, so the
mirror changes when a maintainer changes it and not when GitHub rolls a label
over. The cost is that the pin has to be bumped by hand: watch
<https://github.com/actions/runner-images> for the retirement of the image
and move both jobs together. A retired image means the workflow finds no
runner, which is silence rather than a failure — the healthchecks alert
below is what catches it.

## Retiring data

The repository stays small enough for GitHub for years, but if it ever grows
past a gigabyte, move whole `data/<operator>/<shard>/` directories of closed
shards into GitHub Releases or a separate archive repository. Never rewrite
history; the value of the mirror is that its history is boring. Note that
moving a shard out makes the `+` markers in past commit messages impossible to
check, and wrong in future ones for names that were only ever seen there.

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

## What a sync commit says

`ructmirror summary` turns the chunk files a run added into that run's commit
message. A run only ever adds chunks and never rewrites one, so the message is
derived from the commit's own diff and anyone with a clone can recompute it:

```
sync 2026-09-19T18:23:07Z: 14 entries, 9 names (3 new)

digital-gov/2026  [8745, 8749]   5 entries
vk/2026           [6144, 6144]   1 entry
yandex/2027       [9932, 9939]   8 entries

Names in the added chunks, + when new to this mirror:

+ api.gosuslugi.ru
  lk.gosuslugi.ru
+ xn--d1aqf.xn--p1ai (дом.рф)
```

`+` means the name appears in no chunk this run did not add. That is first
appearance **in this mirror**, not first issuance: the Ministry's 2022-2024
shards were already gone when the mirror started, so a name first certified
there looks new here the day it is renewed. Moving a closed shard out of the
repository has the same effect, which is the other reason to think twice
before doing it.

The subject keeps the `sync <timestamp>` form, so `git log --grep='^sync [0-9]'`
still selects exactly the automated commits. At most 100 names are listed;
`ructmirror domains` and the Pages site have the rest.

A commit whose message is only `sync <timestamp>`, with no body, is not a bug:
the workflow falls back to it whenever the summary fails or runs past its
timeout, because publishing the data matters more than describing it. The same
goes for a message that lists names without `+` markers — it means the scan of
the rest of the mirror did not finish in time.

Names are printed as the certificate carries them, and certificates here are
signed by the CA this repository exists to watch. A name outside
`a-z 0-9 . - _ *` is quoted, anything over 100 runes is cut, and the Unicode
reading of an IDN is shown only when the decoded label re-encodes to exactly
the stored one, contains no control, bidi, invisible or combining characters,
and each label is written in a single script. That strictness is deliberate:
by the rule above, a wrong or hostile name in a commit message cannot be taken
back.

The workflow also prints the message into the job log and sends its first
lines to healthchecks, so a run whose push fails still says what it saw. The
log copy is fenced with `::stop-commands::` and a random token, because the
runner reads its own commands out of the log and a name is not ours to trust.

## Notifications without GitHub e-mail

GitHub refuses alias-style e-mail domains, so the maintainer's notifications
go through [healthchecks.io](https://healthchecks.io) instead. Every run
pings a check with its start, its exit status and a log excerpt; a run that
never happens is noticed as well.

1. Create a check. Schedule: **simple**, period 6 hours, grace time 4 hours.
   Attach whatever notification channels you like (e-mail to any address,
   Telegram, Signal, ...). Enable "notify on start" if you want the duration
   tracked.

   Do not mirror the workflow's cron here. GitHub queues scheduled runs on
   shared runners and fires them hours late: over a week of this repository's
   history the delay against `23 */6 * * *` ranged from 41 minutes to 5h31m
   (median ~4h35m), while the interval between consecutive runs stayed
   between 4h20m and 8h50m. Cron mode measures against the nominal time and
   would need a grace of nearly seven hours to stay quiet; the simple period
   measures the interval between pings, which is what actually holds steady.
   Period plus grace is the silence that triggers an alert — 10 hours here,
   comfortably above the worst observed gap and still below the ~12 hours a
   genuinely skipped run produces.
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

## GitHub Pages

The `pages` job in `sync.yml` runs after every `sync` job, successful or not,
and deploys the output of `ructmirror domains` together with `site/index.html`
and a `meta.json` to <https://ru-ct-mirror.github.io/ru-ct-mirror/>. It
checks out the branch tip (the commit `sync` just pushed), so the site is
never more than one run behind the data. Before building it runs
`ructmirror verify` on that checkout and stops if it fails, so a corrupted or
truncated chunk is never published as verified data; the previous deployment
simply stays up. An unreachable log does not stop it. Nothing it produces is
committed.

One-time setup: Settings → Pages → Build and deployment → Source: **GitHub
Actions**. Until that is done the job fails at `deploy-pages`; it is marked
`continue-on-error`, so the workflow, the issue logic and the healthchecks
ping are unaffected. A fork that does not want a site can simply leave Pages
off.

To rebuild the site by hand, run the `Build site` step's commands locally
and serve `_site/` (`python3 -m http.server -d _site`).

## Two kinds of issues

- **Verification failure <date>**: a log or the log list contradicted
  something the mirror already holds, or served an STH too old to be a
  current statement about the tree (`ructmirror` exited 2, or offline
  `verify` failed). Evidence is committed under `alerts/`. This is the one
  that matters.
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
- `stale-sth`: the log served an STH older than its MMD plus 24 hours. The
  STH still verifies and is still consistent with what we hold: that is the
  point. Either the log has stopped re-signing, or an old STH is being
  replayed at us to hide everything logged since it was signed, and from
  outside the two look identical. Check the log by hand
  (`curl <url>ct/v1/get-sth`) before deciding. A log that has genuinely gone
  dark is marked `"disabled": true` with a note, the way the Ministry's
  2022-2024 shards were; a log that is fresh for everyone but us is the
  finding this mirror exists for.
- `sth-from-future`: the log's STH is timestamped more than ten minutes ahead
  of the runner's clock. An SCT promises inclusion within the MMD of its own
  timestamp, so a log running fast quietly grants itself extra time.

An STH that is older than the MMD but inside the 24-hour grace only prints a
`WARNING` line in the run log. Both thresholds come from Yandex's policy,
which treats a failure exceeding the MMD by more than 24 hours as grounds for
removing the log; VK re-signs its closed shards once a day at 03:42 and
nothing more, so a stricter test would alert on ordinary operation. The `mmd`
field in `logs.json` holds the value copied from `ctlog.json` for each shard
still on Yandex's list; a shard without one is held to RFC 6962's own 24
hours. A shard whose published MMD moves is reported as
`ALERT log list: mmd changed`, because that value is what "stale" means.

In every case `state.json` keeps the last verified tree and the job exits
non-zero after committing the evidence.
