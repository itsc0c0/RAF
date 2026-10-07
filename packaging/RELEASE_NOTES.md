R$F @VERSION@ for Linux, as offline installation bundles: everything R$F needs is inside - a Python
runtime, every dependency, the web workbench and the R$F OS terminal panel - so the installer
downloads nothing and needs no Python, Node.js or Rust on the machine.

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

Linux on x86_64 or aarch64 with glibc 2.17 or newer: Debian, Ubuntu, RHEL/Rocky/Alma 8+, Fedora,
SUSE, Arch ... (not Alpine/musl). Each bundle was installed and used on Debian 12, Ubuntu 24.04,
AlmaLinux 8 and Fedora 42 containers without network access before this release was published.

## Verify

`SHA256SUMS` lists the archives' SHA-256 (`sha256sum -c SHA256SUMS --ignore-missing`); inside each
bundle, `SHA256SUMS` covers every file and `install.sh` checks it before installing anything.

Documentation: [docs/install.md](https://github.com/@REPO@/blob/@TAG@/docs/install.md),
[README](https://github.com/@REPO@/blob/@TAG@/README.md) and the `share/docs` directory of the bundle.
