# ru-ct-mirror

An independent, append-only mirror of the Certificate Transparency (CT) logs
that Yandex Browser trusts for certificates issued by the Russian national CA
(НУЦ Минцифры, "Russian Trusted Root CA").

**Русское резюме внизу.**

## Why

Yandex Browser accepts a certificate from the Russian national CA only if it
carries Signed Certificate Timestamps from CT logs on Yandex's own list
(`https://browser-resources.s3.yandex.net/ctlog/ctlog.json`). Three operators
run such logs: Yandex, VK and the Ministry of Digital Development. All three
logs, the log list itself and both public search front-ends (precert.ru,
ct.tlscc.ru) are hosted inside Russia. None of the global CT infrastructure
(crt.sh, Google's log mirrors, the Internet Archive CT archive) ingests them.

That means an operator could rewrite history and no one outside the country
would hold a contradicting copy. This repository is that copy. Every six hours
a GitHub Actions job running outside Russia:

1. downloads every new entry from every shard,
2. verifies the log's signature on the Signed Tree Head (STH),
3. recomputes the Merkle root from **all** locally stored entries and requires
   it to equal the root the log signed,
4. asks the log for a consistency proof between the previously verified tree
   and the new one and verifies it,
5. records every distinct signed STH it has ever seen,
6. snapshots `ctlog.json` and fails loudly if a log key changes or a log
   appears that is not in `logs.json`,
7. commits the result.

If any check fails the evidence (both STHs, the proof, the entries that were
served) is committed under `alerts/` and an issue titled **Verification
failure** is opened. A log that is merely unreachable opens a **Sync error**
issue instead, so the two never look alike. Every run, successful or not,
can also ping a [healthchecks.io](https://healthchecks.io) check with its exit
status, so a run that silently never happens is noticed too (see
`docs/OPERATIONS.md`). The mirror cannot
stop a rogue certificate from being accepted, but it makes any tampering with
the logs detectable after the fact by anyone holding a clone.

## Layout

```
logs.json                          the shards we mirror, with their public keys and provenance
roots/                             pinned TLS trust anchors used ONLY for *.ctlog.digital.gov.ru
loglist/ctlog.json                 latest snapshot of Yandex Browser's log list (history in git)
data/<operator>/<shard>/
  state.json                       last verified tree size and root hash
  sth.jsonl                        every distinct STH observed, one JSON line each, append-only
  entries/NNNNNNNN-NNNNNNNN.jsonl.gz  immutable chunks: {"index","leaf_input","extra_data"} per line
  alerts/                          exists only if a verification ever failed
```

`leaf_input` and `extra_data` are the exact base64 bytes returned by
`get-entries` (RFC 6962 §4.6), so the Merkle tree can be recomputed from the
files alone.

Operators and shards: `yandex/2022`–`2027` (`ct-agate.yandex.net`),
`vk/2022`–`2027` (`ctlog*.mail.ru`), `digital-gov/2025`–`2027`
(`*.ctlog.digital.gov.ru`). The Ministry's 2022–2024 shards no longer resolve
in DNS; their keys are kept in `logs.json` as `disabled` for the record.

## Verify a clone yourself

```
git clone https://github.com/ru-ct-mirror/ru-ct-mirror
cd ru-ct-mirror
go run ./cmd/ructmirror verify
```

`verify` needs no network. For every shard it re-hashes all stored entries,
checks the root against `state.json` and against the last STH in `sth.jsonl`,
and checks that STH's signature with the key in `logs.json`. Corrupt or
truncate any chunk and it fails.

To compare the mirror with what the logs say right now, run
`go run ./cmd/ructmirror sync` in the clone; it performs the same checks as
the scheduled job.

## See what has been issued

The list of names is published after every run at
<https://ru-ct-mirror.github.io/ru-ct-mirror/>: a page with search and
grouping by registrable domain, plus the raw files `domains-active.txt`
(one active name per line), `domains-active.tsv` and `domains.tsv` (all
names, including expired ones) and `meta.json` (commit and verified tree
size per shard the list was built from). The site is regenerated from the
mirror's data by the same workflow; nothing on it is committed to git.

The same list from a clone, without the network:

```
go run ./cmd/ructmirror domains -active
```

prints one line per DNS name that appears in a stored certificate (SAN or a
host-like CN): how many log entries mention it, how many of those are
precertificates, when it was first logged, the latest expiry and the issuing
CA. Drop `-active` to include expired names. Output is tab-separated for
`sort`, `grep` and friends. This reads only the local files.

## Run your own witness

Fork the repository and enable GitHub Actions on the fork, or run
`ructmirror sync` from any cron outside the operators' reach. Two mirrors that
disagree with each other, or with the log, are exactly the evidence CT is
designed to produce. The more independent witnesses, the less any single one
has to be trusted.

## Where the log keys come from

`ctlog.json` only lists the current shards. Keys for older shards were
recovered from Yandex's own open-source code (`yandex/domestic-roots-patch`,
`yandex/domestic-roots-mobile`) and each key was then confirmed by verifying a
live STH signature from that shard before being written to `logs.json`. The
`key_source` field of every entry records the provenance. `config.Load` also
insists that `sha256(key) == log_id`.

The pinned TLS chain in `roots/` (root fingerprint
`D2:6D:2D:02:31:B7:C3:9F:92:CC:73:85:12:BA:54:10:35:19:E4:40:5D:68:B5:BD:70:3E:97:88:CA:8E:CF:31`)
is used exclusively to reach the Ministry's log servers, which present a
certificate from the national CA and omit the intermediate. It is never added
to the system trust store.

## Limits

- This is detection, not prevention. Yandex Browser trusts only Yandex's list.
- Certificates the CA issues without logging are invisible here, but the
  browser rejects those too.
- The Ministry's 2022–2024 logs were gone before this mirror started.
- A run every six hours means a split view that is shown to the browser for
  less than six hours and then healed could be missed. Run more witnesses.

## Русское резюме

Яндекс Браузер принимает сертификаты НУЦ Минцифры только с метками SCT из
CT-логов Яндекса, VK и Минцифры. Все три лога и список доверенных логов
хостятся в России, вне страны копий не было. Этот репозиторий раз в шесть
часов из GitHub Actions скачивает все новые записи, проверяет подпись STH,
пересчитывает Merkle-корень по всем сохранённым записям, проверяет
consistency proof, фиксирует каждый подписанный STH и коммитит результат.
Любое расхождение попадает в `alerts/` и в issue. Список имён, на которые
выписаны сертификаты, публикуется после каждого запуска на
<https://ru-ct-mirror.github.io/ru-ct-mirror/> (поиск, группировка по домену
второго уровня, файлы TSV/TXT). Проверить свой клон без
сети: `go run ./cmd/ructmirror verify`. Поднять второго свидетеля: форк и
включить Actions.

## License

Apache-2.0.
