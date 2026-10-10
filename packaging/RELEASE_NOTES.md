R$F @VERSION@ for Linux, as offline installation bundles: everything R$F needs is inside - a Python
runtime, every dependency, the web workbench and the R$F OS terminal panel - so the installer
downloads nothing and needs no Python, Node.js or Rust on the machine.

## What's new in 0.2.0

* **Mixed and multi-source logs.** The new `multilog` parser decodes every line of a log on its own,
  so one file can interleave web servers, AWS CloudTrail, Kubernetes audit, identity providers (Okta,
  Azure AD and others), DNS servers, PostgreSQL, Windows/Sysmon, EDR, Suricata/Zeek, flows, CEF/LEEF,
  auditd, Cisco ASA, Squid, S3 access logs, application JSON, key=value and free text. Sessions,
  request IDs, status and error codes, SQL statements, process trees and every unmapped field are
  kept; credential values are redacted, and access key IDs become `secret` objects with a redacted
  name and a SHA-256 fingerprint. See [docs/logs.md](https://github.com/@REPO@/blob/@TAG@/docs/logs.md).
* **Detections.** `raf detect`, a Detections step in `raf analyze` and `POST /api/v1/timeline/detect`
  run 20 rules over normalized events from any source (exposed and misused credentials, bulk storage
  reads, large transfers, persistence attempts, brute force and password spraying, MFA fatigue,
  destructive changes, log tampering, suspicious commands and SQL, DNS tunneling ...), each finding
  with its evidence and ATT&CK techniques. Activity covered by an approved change, a ticket or a
  scheduled job is explained instead of flagged; detections that share pivots are correlated into a
  suspected incident (`CASE-...`) or matched to an existing one.
* **Earlier imports are re-read.** Data imported before with another parser (a mixed log that 0.1.0
  read as plain text) is re-read in place by `raf analyze <file>`: its events keep their identity,
  import job and incident links.

## Upgrading from 0.1.0

Run the new bundle's installer: it upgrades the installation in place, and workspaces in `~/.raf`
need no migration. For the new parsing of a log imported with 0.1.0, analyze it again
(`raf analyze <file>`); `raf detect` runs the detections over the whole workspace.

## Install

Pick the bundle for your machine (`uname -m`: `x86_64` or `aarch64`), unpack it and run the installer:

```sh
curl -LO https://github.com/@REPO@/releases/download/@TAG@/raf-@VERSION@-linux-x86_64.tar.gz
tar -xzf raf-@VERSION@-linux-x86_64.tar.gz
cd raf-@VERSION@-linux-x86_64
sudo ./install.sh
```

The `.zip` holds the same bundle: `unzip raf-@VERSION@-linux-x86_64.zip && cd raf-@VERSION@-linux-x86_64 && sudo sh install.sh`.

R$F goes to `/opt/raf`, and `raf` and `raf-os` are linked into `/usr/local/bin`. Without root,
`./install.sh --user` installs into `~/.local/opt/raf` with links in `~/.local/bin`. Running a newer
bundle's installer upgrades in place (the previous installation comes back if anything fails);
`sudo /opt/raf/uninstall.sh` removes it. Your data stays in `~/.raf` either way.

Then:

```sh
raf demo load     # the demo workspace (fictional Raven Industries)
raf analyze       # every analysis
raf serve         # web workbench on http://127.0.0.1:8765
raf tui           # R$F OS, the full-screen terminal panel
```

## Requirements

Linux with glibc @GLIBC_X86_64@ or newer on x86_64, @GLIBC_AARCH64@ or newer on aarch64: Debian, Ubuntu,
RHEL/Rocky/Alma 8+, Fedora, SUSE, Arch ... (not Alpine/musl). Each bundle was installed and used on Debian 12, Ubuntu 24.04,
AlmaLinux 8 and Fedora 42 containers without network access before this release was published.

## Verify

`SHA256SUMS` lists the archives' SHA-256 (`sha256sum -c SHA256SUMS --ignore-missing`); inside each
bundle, `SHA256SUMS` covers every file and `install.sh` checks it before installing anything.

Documentation: [docs/install.md](https://github.com/@REPO@/blob/@TAG@/docs/install.md),
[README](https://github.com/@REPO@/blob/@TAG@/README.md) and the `share/docs` directory of the bundle.
