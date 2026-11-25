# 源码来源

PS Accel 的提码率协议、中继与恢复代码源自：

- [dy0422/ps5-portal-high-bitrate-openwrt](https://github.com/dy0422/ps5-portal-high-bitrate-openwrt)，固定提交 `56f655275ebe941e7bb49f8f69c3f4ac2abe5753`。
- 原始项目 [atameric/ps5-portal-high-bitrate](https://github.com/atameric/ps5-portal-high-bitrate)，原版移植所基于的提交 `4430daaa0ea9f2baa498fee45540f6f8f4e19617`。

保留原作者 atameric 的 MIT 许可，见 `LICENSE`。本目录采用独立的 `ps-accel` 服务、UCI 配置、网络命名空间与 LuCI 页面；共享协议引擎锁实现与原插件的互斥运行。

本地变更包括中文 Tab 控制台、低码率档位、运行中换档与失败回退、配置与测试记录管理、有界后台日志与统计、诊断导出和 ARM64 主路由部署说明。握手匹配条件、LaunchSpec 字节偏移、UDP 校验与原有单向引流方式沿用原项目。

质量采集参考 [Chiaki-ng](https://github.com/streetpea/chiaki-ng) 的 Takion 拥塞反馈与控制消息布局，参考提交为 `4a0115e1b3fd3dd98384962b9779dea866122ba5`。`stream_quality.py` 按公开报文结构独立实现被动计数与只读建议，保持认证字段与原始报文透传。
