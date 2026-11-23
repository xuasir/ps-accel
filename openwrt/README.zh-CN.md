# PS Accel：OpenWrt 主路由串流增强

基准环境为已验证原方案有效的 **FastRhino R66S / rockchip/armv8 / OpenWrt 25.12-SNAPSHOT / Linux 6.12.115**。本套件在原有提码率链路上重做管理、诊断与部署，服务与配置均独立命名为 `ps-accel`。

## 当前功能（0.1.2）

- 原生中文 LuCI 控制台，状态卡下方使用“串流控制 / 设备配置 / 日志诊断”Tab，支持手机、深浅色与键盘切换。
- 35 / 45 / 65 / 100 / 200 Mbps 档位；运行中保存码率自动重启，保留有效连接测试记录与开机启动偏好。
- 设备配对、60 秒连接测试、90 秒试运行、常驻服务与开机启动。
- 启动时等待主路由网桥就绪；停止命令等待恢复完成后退出。
- 握手修改计数、控制转发采样、任务输出、中继事件与本地诊断导出。
- 日志与统计使用有界后台线程写入，显示写入错误、舍弃日志与合并快照计数。
- 启动失败与取消共用停止恢复流程；子进程执行与退出均有超时，错误分别保留。
- 网络清理支持从中断处重试，清理失败后任务结束，页面保留停止与恢复操作。
- 动态状态、完整配置校验和日志读取分别处理；打开日志 Tab 时读取所选日志。
- UCI 与 LuCI 权限控制、网络命名空间隔离、与原插件互斥运行。

## 在 R66S 上安装

构建安装文件：

```sh
python3 openwrt/build.py
```

`openwrt/release-assets/` 会生成通用脚本安装包、opkg IPK 和 `SHA256SUMS`。

对于截图中的 25.12 系统，优先使用脚本安装包。安装器自动识别 `apk` 或 `opkg`，依赖从主路由当前固件的软件源获取。

先在原提码率插件中停止服务、完成恢复并关闭开机启动，然后上传 `ps-accel-openwrt-0.1.2-1.tar.gz` 到路由器 `/tmp`。在路由器执行：

```sh
cd /tmp
tar xzf ps-accel-openwrt-0.1.2-1.tar.gz
cd ps-accel-openwrt
sh install.sh
ps-accel doctor
```

依赖已经安装时，可使用 `sh install.sh --offline`。脚本安装保留在本机，使用包内的 `uninstall.sh` 管理卸载；`apk` 数据库登记依赖包。原生应用 APK 由下方的固件构建流程生成。

使用 opkg 的系统可安装 `ps-accel_0.1.2-1_all.ipk`：

```sh
opkg update
opkg install /tmp/ps-accel_0.1.2-1_all.ipk
```

内核模块依赖由当前固件软件源解析，`kmod-veth` 版本需与本机内核匹配。程序采用 Python 与 LuCI JavaScript，IPK 的 `all` 表示这些文件独立于 CPU 架构。

已有脚本安装版升级时，进入新安装包目录，停止并卸载旧版后安装。卸载默认保留 UCI、设备配对和测试数据：

```sh
cd /tmp/ps-accel-openwrt
python3 app/portal_openwrt.py stop
sh uninstall.sh
sh install.sh --offline
```

第一条命令使用新包的控制器完成停止恢复，可以处理旧版删除了一部分网络资源的情况。清理失败时保留资源归属记录并报告原因，处理完成后再次执行该命令。

## 配置与运行

LuCI → **服务 → PS Accel 串流增强**。

1. 进入“设备配置”Tab。选择 LAN 网桥，填写一个空闲中继地址，以及 PS5 和 Portal 的地址。保持两台设备开机，点击“保存并检测设备”。
2. 进入“串流控制”Tab，断开 Portal 串流，点击“连接测试 · 60 秒”；在“日志诊断”看到 `BASELINE READY` 后重新连接，检查画面与按键。
3. 点击“试运行 · 90 秒”；日志出现 `AUTO READY` 后重新连接。试运行结束时自动恢复网络。
4. 选择稳定档位，点击“启动中继”。开机启动选项在本次启动时保存。

主路由地址为截图中的 `10.0.0.1`。中继使用独立空闲地址，例如 `10.0.0.250/24`；实际地址以 DHCP 规划为准。

运行中调整码率时，选择新档位并点击“保存并自动重启”。后台任务依次完成旧中继停止、网络恢复、保存档位与新中继启动，页面显示每个阶段。任务完成后重新连接 Portal，新握手使用当前目标码率；启动失败时尝试恢复原档位并重启，失败详情显示在任务输出中。中继已停止时，“保存码率”只保存设置。

原有连接测试在设备、网桥和代码绑定仍有效时继续使用。更改设备地址、MAC、网桥或转发代码后重新完成连接测试。升级到 0.1.2 后，按页面提示重新完成连接测试。

命令行 `ps-accel profile` 用于停止后的单独保存；LuCI 管理任务负责运行中的自动重启流程。

命令行示例：

```sh
ps-accel configure --bridge br-lan --address 10.0.0.250/24 \
  --ps5 10.0.0.100 --portal 10.0.0.101 --profile 65
ps-accel baseline
ps-accel try --seconds 90
ps-accel stop
ps-accel profile --profile 100
```

## 状态与诊断

“目标码率”表示启动请求，“控制转发”表示 Portal → PS5 的中继流量采样。PS5 → Portal 视频沿用设备直达路径。实际画质与视频吞吐通过真实游戏与设备观测评估。

“导出诊断”生成本地 JSON，包含版本、平台、运行计数、测试有效性与恢复状态。设备 IP、MAC、原始任务日志与会话报文保留在路由器。

```sh
ps-accel status
ps-accel doctor
ps-accel stop
ps-accel repair
logread -e ps-accel
```

`ps-accel stop` 会等待主控、引擎与恢复进程退出，完成恢复后返回。procd 保留独立恢复进程的时间窗口；错误状态会保留恢复路径供检查。

LuCI 停止任务共享 120 秒期限，页面显示停止、等待退出和恢复清理阶段。清理失败后任务进入失败状态，错误原因保留在页面和诊断中；“恢复网络”会再次校验仍存在的命名空间及接口归属，从中断步骤继续。状态查询出错时，停止与恢复入口仍可重试。

动态状态每 3 秒刷新，命名空间存在时执行一次有 2 秒期限的进程查询。配置与基线仅在首次加载、操作后或配置、程序变化时重新读取校验；启动前执行完整基线校验。日志 Tab 可见时每次读取所选日志末尾最多 12000 字节。

转发循环把事件和统计快照提交到内存队列，后台线程负责文件写入。日志队列保留 128 条，每条最多 4096 字符；积压时舍弃旧记录，统计快照持续合并为最新值。事件日志每份最多 1 MiB，保留 2 份备份，路径为 `/tmp/ps-accel/events.log`。关闭中继时，诊断线程最多等待 0.2 秒。

“中继状态”依据进程启动身份、命名空间和本次启动的就绪标记。“记录状态”展示日志与统计的健康信息；写入失败或采样陈旧时，已就绪的中继继续显示运行，采样值显示为延迟。设备恢复凭据、恢复标记与引擎就绪信息由控制流程同步保存，保存失败时启动流程完成清理并报告错误。

## 集成到 25.12 固件或 SDK，生成原生 APK

将本目录完整复制到与你的 R66S 固件同版本的 OpenWrt 构建树 `package/ps-accel/`，选择 `Network → ps-accel`，然后执行：

```sh
make package/ps-accel/compile V=s
```

`Makefile` 使用 OpenWrt 的 `BuildPackage`，包格式跟随目标构建树；25.12 的 apk 构建树生成原生 APK。SDK 的固件版本和软件源应与 R66S 当前固件一致。

## 本地开发检查

```sh
python3 -m venv /tmp/ps-accel-venv
/tmp/ps-accel-venv/bin/python -m pip install -r openwrt/requirements.txt
cd openwrt
/tmp/ps-accel-venv/bin/python -m unittest discover -s tests -v
node --check luci/htdocs/luci-static/resources/view/ps-accel/settings.js
node --test tests/test_luci_ui.mjs
python3 build.py
```

浏览器界面预览使用 `preview/index.html`，与安装包加载同一份 LuCI 页面代码。预览以模拟状态驱动，页面顶部明确标注演示数据。

自动化测试覆盖写入失败、写入阻塞、有界日志轮转、自动换档、失败回退、取消交错、子进程回收、部分清理重试、PID 复用、请求超时、按需日志和安装文件完整性。测试结果见 `../docs/verification-0.1.2.zh-CN.md`。

在 R66S 上建议以 65 Mbps 完成连接测试和 90 秒试运行，随后在运行中切换 45 / 100 Mbps，检查自动恢复与重启、开机启动偏好、游戏画面和主路由 CPU。0.1.0 基础安装包保存在 `release-assets/baseline-0.1.0/`。

原有提码率方案的有效性由你的主路由实机测试确认。新版源代码、离线测试、安装包与页面预览在本地验证；新版 R66S 冷启动、实际游戏和原生 APK 安装列入部署验收。源码来源与 MIT 许可见 `UPSTREAM.md`、`LICENSE`。
