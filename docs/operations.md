# Operating an issuer host: what it holds, backup, restore, restart

One box runs the issuer for a small tenant. This page says what on that
box cannot be regenerated, how to copy it, how to put it back, and what a
restart does to work in flight. Paths are those `install-opt.sh` lays
down under `/opt/gargoyle`; `--opt` on the commands names another root.

## Inventory: lose this and you lose

`gargoyle backup --inventory` prints this table from the code.

| path | kind | lose this and you lose |
|---|---|---|
| `deploy/issuer.env` | secret | the issuer's signing key. Every receipt and witness entry ever signed stops verifying as this issuer's; a new key is a new issuer |
| `deploy/holds.sqlite` | sqlite | open holds, grants waiting to be collected, declines and their reasons, the decline cooldown, plans: the approvers' pending work and the gate's uncollected grants |
| `deploy/witness.jsonl` | append | the issuer's signed record of every decision, the chain clients reconcile their evidence against. Its horizon moves to the restore |
| `deploy/approvers.json` | secret | enrolled approvers' public keys, current and retired. Grants under those keys stop verifying in audits; every approver enrols again |
| `deploy/public-keys.json` | config | the trust roots clients copy |
| `deploy/approver.env`, `deploy/approver-web.json` | secret | the terminal and file-based approver keys |
| `deploy/rules.json`, `deploy/record.json` | config | the policy and its published pin |
| `deploy/mcp-config.json`, `deploy/middleware.env` | config, secret | the local gate's entry and executor key |
| `tls/` | tree | the certificate and private key clients pin; a new one must be redistributed |
| `secrets/` | tree | the OAuth broker's client secret and other service secrets |
| `deploy/<gate>/audit.jsonl` | append | that remote gate's evidence log: what ran, with receipts |
| `deploy/<gate>/audit.replay.sqlite` | sqlite | the single-use claims; a receipt honored before the loss could be honored again within its lifetime |
| `deploy/<gate>/snapshots/` | tree | pre-change snapshots: undo of held changes before the loss |
| `deploy/<gate>/gate.env`, `middleware.env`, `remote-tokens.json`, `oauth-state.json` | config, secret | the gate's settings, executor key, capability tokens, OAuth state |

Not state: the venv, `logs/`, `.cache/`, `holds.sqlite-wal` and `-shm`
(folded into the copy by the online backup), `*.lock`.

## Backup

```
sudo /opt/gargoyle/venv/bin/gargoyle backup /var/backups/gargoyle \
     --extra /etc/systemd/system/gargoyle.service --extra /etc/systemd/system/gargoyle-remote@.service
```

Stop-free. The hold store is copied with SQLite's online backup API, a
consistent snapshot while the issuer writes; the append-only files and
configuration are copied as they are. The copied witness is verified
against the copied issuer key before anything is written: a backup of a
broken chain is refused, exit 1. The archive is
`gargoyle-backup-<UTC stamp>-w<witness seq>-<head hash 8>.tar.gz`, mode
0600 (it holds private keys), with a `MANIFEST.json` naming every file's
SHA-256, the witness head, hold counts and the gates present.

Daily is enough for a small tenant: the witness and evidence logs are
append-only and a day's holds are few. Keep the archives off the box.
`deploy/gargoyle-backup.timer` in the deployment repository runs it
nightly; a cron line does the same.

What the backup does not do: it does not copy the Windows workstations'
own evidence logs (`C:\gargoyle\audit.jsonl`) or snapshots. Those are the
clients' records of what ran; the witness on the issuer says what was
decided. Back them up with the workstation.

## Restore

```
sudo systemctl stop gargoyle-remote@files.service gargoyle.service
sudo /opt/gargoyle/venv/bin/gargoyle restore /var/backups/gargoyle/gargoyle-backup-….tar.gz --force
sudo chown -R gargoyle:gargoyle /opt/gargoyle/deploy /opt/gargoyle/tls
sudo systemctl start gargoyle.service gargoyle-remote@files.service
```

`restore` extracts to a temporary directory first and checks every file
against the manifest, the witness against the issuer key, and the hold
store with `integrity_check`; a failure refuses with nothing written.
Then, with `--force`, whatever is at the inventory paths now is moved to
`<opt>/pre-restore-<stamp>/`, never overwritten, and the archive's files
are put in place with secrets at mode 0600. `--verify-only` does the
checks and writes nothing; `--inspect` prints the manifest.

After the restart, `gargoyle doctor` on a workstation should show the
same rules pin and a witness head at or past the archive's. An approver's
open card from before the backup is still there to release; grants that
were collected after the backup are gone, and the gate that collected
them has the execution receipts in its evidence log, which `gargoyle
audit --witness` will now report as honored rows the witness cannot
vouch for past the restore point. That is the honest statement of what a
restore costs: the decisions between backup and loss.

## Restart

`systemctl restart gargoyle.service` is safe at any time. The hold store
is SQLite, so open holds, uncollected grants, declines and the cooldown
memory survive; the witness is appended with a `started` entry marked
`resumed`, so the record shows the restart; the pin is recomputed from
the rules file. The test `test_holds_grants_and_declines_survive_a_restart`
opens a hold, restarts the app on the same store, releases the hold, and
restarts twice more to find the grant and then the decline where they
were left. On the pilot host the witness records eighteen starts in three days
of code updates, with holds in various states and nothing lost.

The remote gate (`gargoyle-remote@<name>`) `Requires=` the issuer and
restarts with it. The Windows stdio gate is per Claude Code session and
needs nothing.

## One issuer per tenant

A second issuer sharing the tenant would need a shared witness, since the
chain is one sequence; that is a design change, recorded as a later goal
in the roadmap, not a fix. For a small business one issuer is acceptable
when the backup is daily and a restore from the archive takes under an
hour on a fresh box: install-opt.sh, restore, start. The exposure is one
day of decisions and the holds open at the moment of loss.

## Witness size

One entry is about 880 bytes. The pilot recorded 614 entries in three
days of heavy testing, roughly 540 KB. A tenant gating 200 calls a day
writes about 65 MB a year. The issuer loads the file at start and serves
it from memory, so a year is fine and five are fine; there is no
rotation, because the chain is one sequence and the archive is the
backup. When a tenant outgrows that, a `witness rotate` that seals the
file and starts a new one from the old tail hash is the right tool; it is
not written yet.
