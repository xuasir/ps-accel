include $(TOPDIR)/rules.mk

PKG_NAME:=ps-accel
PKG_VERSION:=0.1.2
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=PS Accel
APP_FILES:=portal_auto.py portal_auto_platform.py portal_active_probe.py portal_capture.py portal_egress_witness.py portal_windows_network.py protocol.py profiles.py telemetry.py portal_openwrt.py portal_luci.py

include $(INCLUDE_DIR)/package.mk

define Package/ps-accel
  SECTION:=net
  CATEGORY:=Network
  TITLE:=PS Accel - PlayStation Portal local streaming control
  DEPENDS:=+python3 +scapy +ip-full +kmod-veth +libpcap +luci-base +rpcd
  PKGARCH:=all
endef

define Package/ps-accel/description
  Native LuCI controls, fixed bitrate profiles and an isolated LAN relay.
  Baseline environment: FastRhino R66S, rockchip/armv8, OpenWrt 25.12.
endef

define Package/ps-accel/conffiles
/etc/config/ps_accel
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
rm -rf /usr/lib/ps-accel/__pycache__
rm -f /tmp/luci-indexcache*
if /etc/init.d/rpcd running >/dev/null 2>&1; then /etc/init.d/rpcd reload; fi
echo '安装完成。进入 服务 → PS Accel 串流增强，检测设备并完成连接测试。'
exit 0
endef

define Package/ps-accel/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
/usr/sbin/ps-accel stop || exit 1
/etc/init.d/ps-accel disable
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
