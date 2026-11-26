# LuCI 原生风格预览

`index.html` 使用插件同一份 `settings.js`，由演示 RPC 提供数据。安装后的插件使用固件当前 LuCI 主题；预览使用随附的 LuCI Bootstrap 样式，按钮切换主题原生的 `data-darkmode` 状态。

透明代理预览直接展示本机 PassWall 的代理、直连名单、保存与应用状态，域名监控预览包含正在采集和已归档的连接批次、失败解析筛选、PassWall 纯域名复制、批次流量排序及代理清单联动；提供代理大流量与固件直连下载示例，新建批次后会补充演示记录。

`luci-bootstrap.css` 与 `luci-bootstrap-mobile.css` 来自 Kwrt R66S `25.12-SNAPSHOT` 镜像中的 `/www/luci-static/bootstrap/`，保留原文件的版权与许可证声明。上游为 [LuCI Bootstrap](https://github.com/openwrt/luci/tree/master/themes/luci-theme-bootstrap)，Apache-2.0 许可证。

许可证全文见 [LICENSE.bootstrap](LICENSE.bootstrap)。

构建命令 `python3 openwrt/build.py` 将这两份预览样式及当前页面内嵌到独立 HTML。插件安装包仅包含页面及布局 CSS，配色、边框、控件与标签页样式由已安装的 LuCI 主题提供。

0.1.6 的历史预览包含动态域名批量补充、核心实际出口与固定目标检测。当前页面采用原生 PassWall 名单维护。[验收截图](proxy-alignment-0.1.6.jpg) 使用演示数据，码率增强与透明代理同时运行。
