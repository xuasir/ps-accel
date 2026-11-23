#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root.' >&2; exit 1; }
if command -v apk >/dev/null 2>&1 && apk info -e ps-accel >/dev/null 2>&1; then
	exec apk del ps-accel
fi
if command -v opkg >/dev/null 2>&1 && opkg status ps-accel 2>/dev/null | grep -q 'Status:.* installed'; then
	exec opkg remove ps-accel
fi
if [ -x /usr/sbin/ps-accel ]; then
	/usr/sbin/ps-accel stop
fi
if [ -x /etc/init.d/ps-accel ]; then
	/etc/init.d/ps-accel disable
fi
[ ! -e /var/run/netns/ps-accel ] || { echo 'Recovery namespace remains. Files retained.' >&2; exit 1; }
rm -f /usr/sbin/ps-accel /etc/init.d/ps-accel
rm -rf /usr/lib/ps-accel
rm -f /usr/libexec/rpcd/ps-accel
rm -f /usr/share/rpcd/acl.d/luci-app-ps-accel.json
rm -f /usr/share/luci/menu.d/luci-app-ps-accel.json
rm -f /www/luci-static/resources/view/ps-accel/settings.js
rm -f /tmp/luci-indexcache*
if /etc/init.d/rpcd running >/dev/null 2>&1; then /etc/init.d/rpcd reload; fi
echo 'Removed. Configuration/enrollment retained in /etc/config/ps_accel and /etc/ps-accel.'
echo 'Distribution dependencies retained for other packages.'
