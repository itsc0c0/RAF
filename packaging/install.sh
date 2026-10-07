#!/bin/sh
# R$F installer: installs this bundle into /opt/raf and links `raf` and `raf-os` into /usr/local/bin.
#
#   sudo ./install.sh                         install, or upgrade an earlier installation
#   ./install.sh --user                       for the current user: ~/.local/opt/raf, links in ~/.local/bin
#   sudo ./install.sh --prefix DIR --bin-dir DIR
#
# Everything is inside the bundle - a Python runtime, every dependency as a wheel, the web
# workbench, the raf-os terminal panel, documentation and the demo fixtures - so nothing is
# downloaded. Only the prefix directory and the two links are written; no service is started and
# no system file is changed. User data stays in ~/.raf (RAF_HOME) and survives upgrades and
# uninstalling. Run ./install.sh --help for every option.
set -eu
umask 022

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
MARKER=.raf-install

say() { printf '%s\n' "$*"; }
step() { printf '  - %s\n' "$*"; }
die() {
	printf 'install.sh: %s\n' "$*" >&2
	exit 1
}
field() { sed -n "s/^$1=//p" "$HERE/BUNDLE" | head -n 1; }

usage() {
	cat <<'EOF'
Usage: ./install.sh [options]

Installs R$F from this bundle (offline). Default: /opt/raf, links in /usr/local/bin (needs root).

Options:
  --prefix DIR     install into DIR (default /opt/raf)
  --bin-dir DIR    put the raf and raf-os links into DIR (default /usr/local/bin)
  --user           install for the current user: ~/.local/opt/raf, links in ~/.local/bin
  --no-link        do not create links (run DIR/bin/raf)
  --force          replace a directory that is not an R$F installation (it is kept aside),
                   and links named raf/raf-os that point elsewhere
  --skip-verify    do not check the bundle's SHA-256 sums (not recommended)
  -h, --help       show this help

Uninstall: sudo /opt/raf/uninstall.sh (user data in ~/.raf is kept).
EOF
}

[ -f "$HERE/BUNDLE" ] || die "BUNDLE is missing: run install.sh from the unpacked R\$F bundle"
VERSION=$(field version)
ARCH=$(field arch)
GLIBC_MIN=$(field glibc_min)
PYTHON_ARCHIVE=$(field python_archive)
EXTRAS=$(field extras)

PREFIX=/opt/raf
BIN_DIR=/usr/local/bin
LINK=1
FORCE=0
VERIFY=1
while [ $# -gt 0 ]; do
	case $1 in
	--prefix)
		[ $# -ge 2 ] || die "--prefix needs a directory"
		PREFIX=$2
		shift 2
		;;
	--prefix=*)
		PREFIX=${1#*=}
		shift
		;;
	--bin-dir)
		[ $# -ge 2 ] || die "--bin-dir needs a directory"
		BIN_DIR=$2
		shift 2
		;;
	--bin-dir=*)
		BIN_DIR=${1#*=}
		shift
		;;
	--user)
		[ -n "${HOME:-}" ] || die "--user needs HOME"
		PREFIX=$HOME/.local/opt/raf
		BIN_DIR=$HOME/.local/bin
		shift
		;;
	--no-link)
		LINK=0
		shift
		;;
	--force)
		FORCE=1
		shift
		;;
	--skip-verify)
		VERIFY=0
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*) die "unknown option: $1 (see --help)" ;;
	esac
done

# -- where ---------------------------------------------------------------------------------------

case $PREFIX in
/*) ;;
*) die "--prefix must be an absolute path: $PREFIX" ;;
esac
case $BIN_DIR in
/*) ;;
*) die "--bin-dir must be an absolute path: $BIN_DIR" ;;
esac
while [ "${PREFIX%/}" != "$PREFIX" ]; do PREFIX=${PREFIX%/}; done
case $PREFIX in
"" | /bin | /boot | /dev | /etc | /home | /lib | /lib64 | /opt | /proc | /root | /run | /sbin | /sys | /tmp | /usr | /usr/* | /var)
	case $PREFIX in
	/usr/local/*) ;;
	*) die "refusing to install into $PREFIX: choose a directory of its own, such as /opt/raf" ;;
	esac
	;;
esac

# -- this machine --------------------------------------------------------------------------------

[ "$(uname -s)" = Linux ] || die "this bundle is for Linux"
machine=$(uname -m)
case $machine in
amd64) machine=x86_64 ;;
arm64) machine=aarch64 ;;
esac
[ "$machine" = "$ARCH" ] || die "this bundle is for $ARCH, this machine is $machine: download raf-$VERSION-linux-$machine"

if ldd --version 2>&1 | grep -qi musl; then
	die "this system uses musl libc (Alpine): the bundle needs glibc $GLIBC_MIN or newer (Debian, Ubuntu, RHEL, Fedora, SUSE ...); in containers, use a glibc base image"
fi
glibc=$(getconf GNU_LIBC_VERSION 2>/dev/null | sed -n 's/^glibc //p')
[ -n "$glibc" ] || die "could not find the glibc version (getconf GNU_LIBC_VERSION): glibc $GLIBC_MIN or newer is needed"
version_at_least() { # $1 >= $2 (X.Y)
	a1=${1%%.*} a2=${1#*.} b1=${2%%.*} b2=${2#*.}
	a2=${a2%%.*} b2=${b2%%.*}
	[ "$a1" -gt "$b1" ] || { [ "$a1" -eq "$b1" ] && [ "$a2" -ge "$b2" ]; }
}
version_at_least "$glibc" "$GLIBC_MIN" || die "glibc $glibc is too old: this bundle needs glibc $GLIBC_MIN or newer"
for tool in tar gzip sed; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is needed"
done

# -- the bundle ----------------------------------------------------------------------------------

if [ "$VERIFY" = 1 ]; then
	if command -v sha256sum >/dev/null 2>&1; then
		(cd "$HERE" && sha256sum -c SHA256SUMS >/dev/null 2>&1) || die "checksum mismatch: the bundle is damaged or was modified (sha256sum -c SHA256SUMS)"
	elif command -v shasum >/dev/null 2>&1; then
		(cd "$HERE" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1) || die "checksum mismatch: the bundle is damaged or was modified"
	else
		die "sha256sum is missing (coreutils): install it, or pass --skip-verify"
	fi
fi

# -- permissions and an earlier installation ---------------------------------------------------

parent=$(dirname -- "$PREFIX")
mkdir -p -- "$parent" 2>/dev/null || true
if [ ! -w "$parent" ]; then
	die "cannot write to $parent: run as root (sudo ./install.sh) or install for your user (./install.sh --user)"
fi
if [ "$LINK" = 1 ]; then
	mkdir -p -- "$BIN_DIR" 2>/dev/null || true
	[ -w "$BIN_DIR" ] || die "cannot write to $BIN_DIR: run as root, choose --bin-dir, or pass --no-link"
	for name in raf raf-os; do
		target=$BIN_DIR/$name
		if [ -e "$target" ] || [ -L "$target" ]; then
			current=$(readlink -- "$target" 2>/dev/null || true)
			case $current in
			"$PREFIX"/*) ;;
			*) [ "$FORCE" = 1 ] || die "$target exists and is not an R\$F link: remove it, choose --bin-dir, or pass --force" ;;
			esac
		fi
	done
fi

BACKUP=
PREVIOUS=
CREATED=0
scratch=
if [ -e "$PREFIX" ] || [ -L "$PREFIX" ]; then
	if [ -f "$PREFIX/$MARKER" ]; then
		PREVIOUS=$(sed -n 's/^version=//p' "$PREFIX/$MARKER")
	elif [ -d "$PREFIX" ] && [ -z "$(ls -A -- "$PREFIX")" ]; then
		rmdir -- "$PREFIX"
	elif [ "$FORCE" != 1 ]; then
		die "$PREFIX exists and is not an R\$F installation: choose another --prefix, or pass --force (it is kept aside)"
	fi
	if [ -e "$PREFIX" ]; then
		BACKUP=$PREFIX.previous-$(date +%Y%m%d%H%M%S)
		mv -- "$PREFIX" "$BACKUP"
	fi
fi

finish() {
	status=$?
	if [ -n "$scratch" ]; then rm -rf -- "$scratch"; fi
	if [ "$status" -ne 0 ]; then
		if [ "$CREATED" = 1 ]; then rm -rf -- "$PREFIX"; fi
		if [ -n "$BACKUP" ] && [ -e "$BACKUP" ]; then
			mv -- "$BACKUP" "$PREFIX" && say "install.sh: the previous installation was restored" >&2
		fi
		say "install.sh: installation failed (exit $status); nothing else was changed" >&2
	fi
}
trap finish EXIT
trap 'exit 130' INT TERM HUP

# -- install -------------------------------------------------------------------------------------

# the bundled Python and pip must not pick up settings meant for another Python
unset PYTHONHOME PYTHONPATH PYTHONSTARTUP PYTHONUSERBASE
for name in $(env | sed -n 's/^\(PIP_[A-Z0-9_]*\)=.*/\1/p'); do unset "$name"; done

if [ -n "$PREVIOUS" ]; then
	say "Upgrading R\$F $PREVIOUS to $VERSION in $PREFIX"
else
	say "Installing R\$F $VERSION into $PREFIX"
fi
mkdir -p -- "$PREFIX"
CREATED=1

step "Python runtime ($(field python))"
tar -xzf "$HERE/runtime/$PYTHON_ARCHIVE" -C "$PREFIX"
[ -x "$PREFIX/python/bin/python3" ] || die "the Python runtime did not unpack"
"$PREFIX/python/bin/python3" -m venv "$PREFIX/venv"

step "R\$F $VERSION and its dependencies (offline, from the bundle's wheels)"
PIP_CONFIG_FILE=/dev/null PIP_NO_INPUT=1 "$PREFIX/venv/bin/python" -m pip install \
	--no-index --find-links "$HERE/wheels" --no-cache-dir --disable-pip-version-check \
	--no-warn-script-location --quiet "raf[$EXTRAS]==$VERSION"

step "R\$F OS terminal panel (raf-os)"
cp -- "$HERE/bin/raf-os" "$PREFIX/venv/bin/raf-os"
chmod 0755 "$PREFIX/venv/bin/raf-os"
mkdir -p -- "$PREFIX/bin"
ln -s ../venv/bin/raf "$PREFIX/bin/raf"
ln -s ../venv/bin/raf-os "$PREFIX/bin/raf-os"

step "documentation, demo fixtures and examples ($PREFIX/share)"
mkdir -p -- "$PREFIX/share"
cp -R -- "$HERE/share/." "$PREFIX/share/"
for file in VERSION LICENSE README.txt BUNDLE; do
	cp -- "$HERE/$file" "$PREFIX/$file"
done
cp -- "$HERE/uninstall.sh" "$PREFIX/uninstall.sh"
chmod 0755 "$PREFIX/uninstall.sh"

step "checking the installation"
# a scratch RAF_HOME: never create ~/.raf as root in a home that sudo kept (it would lock its user out)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/raf-install.XXXXXX")
RAF_HOME=$scratch "$PREFIX/bin/raf" --version >/dev/null || die "raf does not start"
RAF_HOME=$scratch "$PREFIX/bin/raf" --quiet products >/dev/null || die "raf cannot load its products"
rm -rf -- "$scratch"
scratch=
"$PREFIX/bin/raf-os" --version >/dev/null || die "raf-os does not start"

LINKS=
if [ "$LINK" = 1 ]; then
	for name in raf raf-os; do
		ln -sfn -- "$PREFIX/bin/$name" "$BIN_DIR/$name"
		LINKS="$LINKS $BIN_DIR/$name"
	done
	step "links:$LINKS"
fi

{
	printf 'version=%s\n' "$VERSION"
	printf 'arch=%s\n' "$ARCH"
	printf 'prefix=%s\n' "$PREFIX"
	printf 'links=%s\n' "${LINKS# }"
	printf 'installed=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$PREFIX/$MARKER"

CREATED=0
trap - EXIT
if [ -n "$BACKUP" ]; then
	if [ -n "$PREVIOUS" ]; then
		rm -rf -- "$BACKUP" || say "  - note: could not remove the previous installation at $BACKUP"
	else
		say "  - the directory that was at $PREFIX is kept at $BACKUP"
	fi
fi

raf=$PREFIX/bin/raf
if [ "$LINK" = 1 ]; then
	case ":${PATH:-}:" in
	*":$BIN_DIR:"*) raf=raf ;;
	*) say "  - note: $BIN_DIR is not on your PATH; add it, or run $PREFIX/bin/raf" ;;
	esac
fi
cat <<EOF

R\$F $VERSION is installed. Try:

  $raf demo load      load the demo workspace (fictional Raven Industries)
  $raf analyze        run every analysis on the current workspace
  $raf serve          web workbench on http://127.0.0.1:8765 (loopback only)
  $raf tui            R\$F OS, the full-screen terminal panel

Documentation: $PREFIX/share/docs (start with README.md)
Your data:     ~/.raf of whoever runs raf, or \$RAF_HOME (kept on upgrade and uninstall)
Uninstall:     $PREFIX/uninstall.sh
EOF
