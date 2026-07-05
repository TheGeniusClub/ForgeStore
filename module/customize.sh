#!/system/bin/sh
# Copyright (C) 2026  TheGeniusClub
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <https://www.gnu.org/licenses/>.

SKIPUNZIP=1

if [ "$BOOTMODE" ]; then
    ui_print "- Installing from ${KSU:+KernelSU}${APATCH:+APatch}${MAGISK:+Magisk} app"
else
    abort "Recovery install not supported"
fi

[ "$API" -lt 29 ] && abort "Minimal supported SDK is 29 (Android 10)"

case "$ARCH" in
    arm64) ARCH_DIR="arm64-v8a" ;;
    arm)   ARCH_DIR="armeabi-v7a" ;;
    x64)   ARCH_DIR="x86_64" ;;
    x86)   ARCH_DIR="x86" ;;
    *)     abort "Unsupported arch: $ARCH" ;;
esac

VERSION=$(grep_prop version "$TMPDIR/module.prop")
ui_print "- ForgeStore $VERSION on $ARCH"

ui_print "- Verifying module integrity"
unzip -o "$ZIPFILE" "verify.sh" -d "$TMPDIR" >&2
source "$TMPDIR/verify.sh"
verify_module "$ZIPFILE"

mkdir -p "$MODPATH/lib"
ui_print "- Extracting module files"
unzip -o "$ZIPFILE" "module.prop" -d "$MODPATH" >&2
unzip -o "$ZIPFILE" "lib/$ARCH_DIR/libforgestore.so" "lib/$ARCH_DIR/libinject.so" -d "$MODPATH" >&2
mv "$MODPATH/lib/$ARCH_DIR/libforgestore.so" "$MODPATH/lib/"
mv "$MODPATH/lib/$ARCH_DIR/libinject.so" "$MODPATH/lib/"
rmdir "$MODPATH/lib/$ARCH_DIR"
unzip -o "$ZIPFILE" "service.apk" -d "$MODPATH" >&2
unzip -o "$ZIPFILE" "daemon" -d "$MODPATH" >&2
unzip -o "$ZIPFILE" "sepolicy.rule" -d "$MODPATH" >&2
unzip -o "$ZIPFILE" "service.sh" -d "$MODPATH" >&2

ui_print "- Setting permissions"
set_perm_recursive "$MODPATH/lib" 0 0 0644 0644
set_perm "$MODPATH/lib/libinject.so" 0 0 0755
set_perm "$MODPATH/service.apk" 0 0 0644
set_perm "$MODPATH/daemon" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755

ui_print "- Setting up config directory"
DATA_DIR="/data/adb/forgestore"
mkdir -p "$DATA_DIR"
[ ! -f "$DATA_DIR/hbk" ] && {
    dd if=/dev/random of="$DATA_DIR/hbk" bs=32 count=1 2>/dev/null
    ui_print "  Generated HBK seed"
}
true
