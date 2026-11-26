include $(TOPDIR)/rules.mk

PKG_NAME:=ps-accel
PKG_VERSION:=0.1.9
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=PS Accel
APP_FILES:=portal_auto.py portal_auto_platform.py portal_active_probe.py portal_capture.py portal_egress_witness.py portal_windows_network.py protocol.py profiles.py telemetry.py observability.py stream_quality.py domain_monitor.py domain_tracker.py portal_observe.py portal_openwrt.py portal_luci.py portal_policy.py passwall_rules.py sony_domains.py proxy_telemetry.py

include $(INCLUDE_DIR)/package.mk

define Package/ps-accel
  SECTION:=net
  CATEGORY:=Network
  TITLE:=PS Accel - PlayStation Portal local streaming control
  DEPENDS:=+python3 +scapy +ip-full +kmod-veth +libpcap +luci-base +rpcd +ca-bundle
  PKGARCH:=all
endef

define Package/ps-accel/description
  Native LuCI controls, fixed bitrate profiles and an isolated LAN relay.
  Baseline environment: FastRhino R66S, rockchip/armv8, OpenWrt 25.12.
endef

define Package/ps-accel/conffiles
/etc/config/ps_accel
/etc/ps-accel/observability.json
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) $(addprefix ./,$(APP_FILES)) ./LICENSE ./requirements.txt ./UPSTREAM* ./files ./luci $(PKG_BUILD_DIR)/
endef

define Build/Compile
endef

define Package/ps-accel/install
	$(INSTALL_DIR) $(1)/usr/lib/ps-accel $(1)/etc/ps-accel
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/*.py $(PKG_BUILD_DIR)/LICENSE $(PKG_BUILD_DIR)/requirements.txt $(PKG_BUILD_DIR)/UPSTREAM* $(1)/usr/lib/ps-accel/
	chmod 700 $(1)/usr/lib/ps-accel $(1)/etc/ps-accel
	chmod 600 $(1)/usr/lib/ps-accel/*
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config $(1)/www
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/ps-accel $(1)/usr/sbin/ps-accel
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/ps-accel.init $(1)/etc/init.d/ps-accel
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/ps-accel-observe $(1)/usr/sbin/ps-accel-observe
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/ps-accel-observe.init $(1)/etc/init.d/ps-accel-observe
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/ps-accel-policy $(1)/usr/sbin/ps-accel-policy
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/ps-accel-policy.init $(1)/etc/init.d/ps-accel-policy
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/files/observability.json $(1)/etc/ps-accel/observability.json
	chmod 600 $(1)/etc/ps-accel/observability.json
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/files/ps_accel $(1)/etc/config/ps_accel
	chmod 600 $(1)/etc/config/ps_accel
	$(CP) $(PKG_BUILD_DIR)/luci/root/. $(1)/
	$(CP) $(PKG_BUILD_DIR)/luci/htdocs/. $(1)/www/
	chmod 755 $(1)/usr/libexec/rpcd/ps-accel
endef

define Package/ps-accel/preinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
if [ -x /usr/sbin/ps-accel ]; then /usr/sbin/ps-accel stop || exit 1; fi
if [ -x /etc/init.d/ps-accel-observe ]; then /etc/init.d/ps-accel-observe stop || exit 1; fi
if [ -x /etc/init.d/ps-accel-policy ]; then /etc/init.d/ps-accel-policy stop || exit 1; fi
if [ -e /var/run/portal-lab-capture.lock ]; then
  echo '请先停止原提码率插件并完成恢复。' >&2
  exit 1
fi
exit 0
endef

define Package/ps-accel/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
uci set ps_accel.main.enabled=0
uci commit ps_accel
/etc/init.d/ps-accel disable
/etc/init.d/ps-accel-observe enable
/etc/init.d/ps-accel-observe start
/usr/sbin/ps-accel-policy migrate || exit 1
/etc/init.d/ps-accel-policy enable
/etc/init.d/ps-accel-policy start
rm -rf /usr/lib/ps-accel/__pycache__
rm -f /tmp/luci-indexcache*
if /etc/init.d/rpcd running >/dev/null 2>&1; then /etc/init.d/rpcd reload; fi
echo '安装完成。进入 服务 → PS Accel，检测设备并完成连接测试。'
exit 0
endef

define Package/ps-accel/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
/usr/sbin/ps-accel stop || exit 1
/etc/init.d/ps-accel disable
/etc/init.d/ps-accel-observe stop || exit 1
/etc/init.d/ps-accel-observe disable
if [ "$$1" != upgrade ]; then /usr/sbin/ps-accel-policy detach || exit 1; fi
/etc/init.d/ps-accel-policy stop || exit 1
/etc/init.d/ps-accel-policy disable
exit 0
endef

define Package/ps-accel/postrm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
[ ! -e /var/run/netns/ps-accel ] || exit 1
rm -rf /usr/lib/ps-accel
rm -f /tmp/luci-indexcache*
if /etc/init.d/rpcd running >/dev/null 2>&1; then /etc/init.d/rpcd reload; fi
exit 0
endef

$(eval $(call BuildPackage,ps-accel))
