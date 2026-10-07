#!/bin/sh
# R$F uninstaller: removes the installation this script belongs to and its raf/raf-os links.
#
#   sudo /opt/raf/uninstall.sh          asks before removing
#   sudo /opt/raf/uninstall.sh --yes    removes without asking
#
# User data (~/.raf of each user, or $RAF_HOME) is never touched: delete it yourself if you want it gone.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
MARKER=.raf-install
YES=0

die() {
	printf 'uninstall.sh: %s\n' "$*" >&2
	exit 1
}

for arg in "$@"; do
	case $arg in
	-y | --yes) YES=1 ;;
	-h | --help)
		sed -n '2,7s/^# \{0,1\}//p' "$0"
		exit 0
		;;
	*) die "unknown option: $arg (see --help)" ;;
	esac
done

[ -f "$HERE/$MARKER" ] || die "$HERE is not an R\$F installation ($MARKER is missing)"
PREFIX=$(sed -n 's/^prefix=//p' "$HERE/$MARKER")
VERSION=$(sed -n 's/^version=//p' "$HERE/$MARKER")
LINKS=$(sed -n 's/^links=//p' "$HERE/$MARKER")
real=$(CDPATH='' cd -- "$PREFIX" 2>/dev/null && pwd -P) || real=
[ "$real" = "$HERE" ] || die "the installation record names $PREFIX, but this script is in $HERE: not removing anything"
[ -w "$(dirname -- "$PREFIX")" ] || die "cannot remove $PREFIX: run as root (sudo $0)"

if [ "$YES" != 1 ]; then
	# shellcheck disable=SC2016 # R$F is the product's name, not a variable
	printf 'Remove R$F %s from %s (and the links%s)? [y/N] ' "$VERSION" "$PREFIX" "${LINKS:+ $LINKS}"
	read -r answer || answer=
	case $answer in
	y | Y | yes | YES) ;;
	*)
		echo "Nothing removed."
		exit 0
		;;
	esac
fi

for link in $LINKS; do
	if [ -L "$link" ]; then
		case $(readlink -- "$link") in
		"$PREFIX"/*) rm -f -- "$link" ;;
		*) printf 'uninstall.sh: %s now points elsewhere: left alone\n' "$link" >&2 ;;
		esac
	fi
done
cd /
rm -rf -- "$PREFIX"
echo "R\$F $VERSION was removed from $PREFIX. User data (~/.raf, \$RAF_HOME) was kept."
