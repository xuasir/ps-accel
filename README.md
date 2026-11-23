# PS Accel

面向 OpenWrt 主路由的 PS5 / PlayStation Portal 本地串流增强套件。

当前基准设备：**FastRhino R66S，rockchip/armv8，OpenWrt 25.12-SNAPSHOT，内核 6.12.115**。原有提码率方案的有效性由本机实测确认，本仓库负责重做中文控制台、配置流程、稳定性和部署。

当前版本 **0.1.2**：统一失败与取消收尾、子进程超时回收、清理中断重试、报文长度保护，以及按需状态与日志读取。中文 Tab 控制台、自动换档重启和有界后台日志继续保留。

- [OpenWrt 安装与使用](openwrt/README.zh-CN.md)
- [仓库分析与增强设计](docs/openwrt-analysis.zh-CN.md)
- [源码来源与 MIT 许可](openwrt/UPSTREAM.md)
- [0.1.2 验证记录](docs/verification-0.1.2.zh-CN.md)
- [中文控制台预览](http://127.0.0.1:8770/preview/index.html)

`openwrt/` 包含独立的 PS Accel 服务、原生 LuCI 页面、协议引擎、测试、IPK/脚本包构建器和 OpenWrt 原生包 Makefile。`PS-Portal-Relay/` 是工作区中的独立登录与信令代理仓库，作为本地参考项目由根 `.gitignore` 排除，保留独立 Git 历史。

## 自动检查与发布

普通分支和 Pull Request 修改 `openwrt/`、GitHub 工作流或根 `.gitignore` 时，会运行 Python 测试、LuCI 页面测试、脚本语法检查并构建安装包。Actions 的 `ps-accel-openwrt` artifact 包含 IPK、通用脚本安装包和 `SHA256SUMS`。

| 推送目标 | 发布类型 | GitHub Release tag |
| --- | --- | --- |
| `release/test` 分支 | 测试版，标记为 Pre-release | `test-<构建编号>-<提交短 SHA>` |
| `v<应用版本>` tag，例如 `v0.1.2` | 正式版，标记为 Latest | 使用推送的版本 tag |

发布流程复用完整检查和构建结果，通过 SHA256 校验后上传到 [GitHub Releases](https://github.com/xuasir/ps-accel/releases)。测试分支的每次推送都会触发发布，正式版由版本 tag 触发。

在本地 `release/test` 分支提交修改后，推送测试版：

```sh
git push origin release/test
```

正式版 tag 与 `openwrt/profiles.py` 的 `APP_VERSION`、`openwrt/build.py` 的安装包版本保持一致。当前版本发布命令：

```sh
git tag v0.1.2
git push origin v0.1.2
```

升级版本时同步更新 `openwrt/profiles.py`、`openwrt/build.py` 和 `openwrt/Makefile`，完成检查后推送对应版本 tag。
