#!/bin/sh
# Build only the IPoE driver when a kernel upgrade has no matching module.
set -eu
kernel=$(uname -r)
case "$kernel" in *[!a-zA-Z0-9._+-]*) echo "Invalid kernel release" >&2; exit 1;; esac
source=/opt/accel-ppp-src
if ! modinfo -k "$kernel" ipoe >/dev/null 2>&1; then
 headers="/lib/modules/$kernel/build"
 test -d "$headers" || { echo "Missing headers for $kernel" >&2; exit 1; }
 build="$source/build-$kernel/ipoe-kernel-module"
 mkdir -p "$build"
 cp "$source/drivers/ipoe/ipoe.c" "$source/drivers/ipoe/ipoe.h" "$source/drivers/ipoe/Makefile" "$build/"
 version=""
 for candidate in "$source/build/version.h" "$source/version.h"; do
  if test -f "$candidate"; then version="$candidate"; break; fi
 done
 test -n "$version" || { echo "Missing accel-ppp version.h" >&2; exit 1; }
 cp "$version" "$build/version.h"
 make -C "$headers" M="$build" -j2 modules
 install -D -m 0644 "$build/ipoe.ko" "/lib/modules/$kernel/extra/ipoe.ko"
 depmod -a "$kernel"
fi
modprobe ipoe
