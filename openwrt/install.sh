#!/bin/sh
# Install the reviewed local bundle; never fetch or execute remote source code.
set -eu
umask 077
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APP=/usr/lib/ps-accel

fail() { echo "ps-accel: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail '请在 OpenWrt 上以 root 执行。'
[ -f /etc/openwrt_release ] || fail '请在 OpenWrt 主路由上执行安装。'
command -v uci >/dev/null 2>&1 || fail '系统需要 UCI。'
[ ! -e "$APP" ] || fail 'PS Accel 已安装。先停止并卸载已有版本，保留配置。'
[ ! -e /etc/init.d/ps-accel ] || fail '系统已有 PS Accel 服务，请先停止并卸载。'
[ ! -e /usr/sbin/ps-accel ] || fail '系统已有 PS Accel 命令，请先停止并卸载。'
[ ! -e /etc/init.d/ps-accel-observe ] || fail '系统已有设备域名观察服务，请先停止并卸载。'
[ ! -e /etc/init.d/ps-accel-policy ] || fail '系统已有域名流量观察服务，请先停止并卸载。'
[ ! -e /var/run/netns/ps-accel ] || fail '请先完成已有中继的网络恢复。'
[ ! -e /var/run/portal-lab-capture.lock ] || fail '请先停止原提码率插件并完成网络恢复。'

case "${1:-}" in
	'') offline=0 ;;
	--offline) offline=1 ;;
	*) fail '用法：sh install.sh [--offline]；卸载使用 sh uninstall.sh。' ;;
esac
[ "$#" -le 1 ] || fail '安装器仅接受 --offline 参数。'

if [ "$offline" = 1 ]; then
	echo '离线安装：检查本机依赖与安装包完整性。'
elif command -v apk >/dev/null 2>&1; then
	echo '使用 apk 安装当前固件依赖。'
	apk update
	apk add python3 scapy ip-full kmod-veth libpcap luci-base rpcd ca-bundle
elif command -v opkg >/dev/null 2>&1; then
	echo '使用 opkg 安装当前固件依赖。'
	opkg update
	opkg install python3 scapy ip-full kmod-veth libpcap luci-base rpcd ca-bundle
else
	fail '请检查本机 apk / opkg 包管理器。'
fi
command -v python3 >/dev/null 2>&1 || fail '需要 python3。'
command -v ip >/dev/null 2>&1 || fail '需要 ip-full。'
[ -d /usr/share/luci ] || fail '需要 luci-base。'
ip netns list >/dev/null || fail '请检查 ip-full 与网络命名空间支持。'

python3 - "$HERE" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
for name, expected in json.loads((root / 'MANIFEST.json').read_text()).items():
    if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
        raise SystemExit('Bundle checksum mismatch: ' + name)
from scapy.arch.common import compile_filter
from scapy.data import DLT_EN10MB
compile_filter('ether dst 02:00:00:00:00:01 and ip', linktype=DLT_EN10MB)
print('安装包 SHA256 与 Scapy/libpcap 检查通过。')
PY

mkdir -p "$APP" /etc/ps-accel
chmod 700 "$APP" /etc/ps-accel
cp "$HERE"/app/* "$APP/"
chmod 600 "$APP"/*
cp "$HERE/files/ps-accel" /usr/sbin/ps-accel
cp "$HERE/files/ps-accel.init" /etc/init.d/ps-accel
cp "$HERE/files/ps-accel-observe" /usr/sbin/ps-accel-observe
cp "$HERE/files/ps-accel-observe.init" /etc/init.d/ps-accel-observe
cp "$HERE/files/ps-accel-policy" /usr/sbin/ps-accel-policy
cp "$HERE/files/ps-accel-policy.init" /etc/init.d/ps-accel-policy
chmod 755 /usr/sbin/ps-accel /etc/init.d/ps-accel /usr/sbin/ps-accel-observe /etc/init.d/ps-accel-observe /usr/sbin/ps-accel-policy /etc/init.d/ps-accel-policy
if [ ! -e /etc/ps-accel/observability.json ]; then
	cp "$HERE/files/observability.json" /etc/ps-accel/observability.json
fi
chmod 600 /etc/ps-accel/observability.json
(
	umask 022
	cp -R "$HERE/luci/root/." /
	cp -R "$HERE/luci/htdocs/." /www/
)
chmod 755 /usr/libexec/rpcd/ps-accel
if [ ! -e /etc/config/ps_accel ]; then
	cp "$HERE/files/ps_accel" /etc/config/ps_accel
fi
chmod 600 /etc/config/ps_accel
uci set ps_accel.main.enabled=0
uci commit ps_accel
/etc/init.d/ps-accel disable
if ! /etc/init.d/ps-accel-observe enable; then echo '域名观察开机启动设置待检查。' >&2; fi
if ! /etc/init.d/ps-accel-observe start; then echo '域名观察启动待检查，串流管理界面可继续使用。' >&2; fi
/usr/sbin/ps-accel-policy migrate
if ! /etc/init.d/ps-accel-policy enable; then echo '域名流量观察开机启动设置待检查。' >&2; fi
if ! /etc/init.d/ps-accel-policy start; then echo '域名流量观察启动待检查。' >&2; fi
rm -f /tmp/luci-indexcache*
if /etc/init.d/rpcd running >/dev/null 2>&1; then /etc/init.d/rpcd reload; fi
echo '安装完成。进入 服务 → PS Accel，检测设备并完成连接测试。'
