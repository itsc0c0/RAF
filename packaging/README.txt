R$F @VERSION@ for Linux @ARCH@ - offline installation bundle
=============================================================

R$F (pronounced RAF) is a defensive security platform: one `raf` command, a local web workbench
and a full-screen terminal panel over one security object model. This bundle holds everything it
needs, so the installation works without network access:

  runtime/   a Python @PYTHON@ runtime (python-build-standalone, used only by R$F)
  wheels/    R$F @VERSION@ (with the built web workbench) and every dependency, PostgreSQL and
             keyring support included
  bin/       raf-os, the R$F OS terminal panel (a static binary)
  share/     documentation (docs/), the demo fixtures (fixtures/) and examples (examples/)

Install
-------

  sudo ./install.sh              into /opt/raf, with raf and raf-os linked into /usr/local/bin
  ./install.sh --user            just for you: ~/.local/opt/raf, links in ~/.local/bin
  ./install.sh --help            every option (--prefix, --bin-dir, --no-link ...)

Running install.sh again with a newer bundle upgrades the installation; if anything fails, the
previous one is restored. The installer checks this bundle's SHA-256 sums first, writes only the
installation directory and the two links, and starts nothing.

Requirements: Linux @ARCH@ with glibc @GLIBC_MIN@ or newer (Debian, Ubuntu, RHEL/Rocky/Alma,
Fedora, SUSE, Arch ...; not Alpine/musl), tar, gzip and sha256sum. Nothing else: no system
Python, no Node.js, no Rust.

First steps
-----------

  raf demo load     load the demo workspace (the fictional Raven Industries)
  raf analyze       run every analysis on it
  raf serve         web workbench on http://127.0.0.1:8765 (loopback only by default)
  raf tui           R$F OS, the full-screen terminal panel
  raf help          commands and topics

Your data lives in ~/.raf of the user who runs raf (or in $RAF_HOME). Upgrades and uninstalling
keep it.

Uninstall
---------

  sudo /opt/raf/uninstall.sh     (or ~/.local/opt/raf/uninstall.sh)

Verify the download
-------------------

The release lists the SHA-256 of every archive (SHA256SUMS); inside the bundle, SHA256SUMS covers
every file and install.sh checks it.

License: Apache License 2.0 (LICENSE). Source: https://github.com/itsc0c0/RAF
