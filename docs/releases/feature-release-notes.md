# 功能发布记录

## 2026-04

| 日期 | 功能域 | 用户价值 | 变更摘要 |
| --- | --- | --- | --- |
| 2026-04-08 | 模板仓库 | 提供了一套可直接用于新项目启动的 Agent-first 基础模板。 | 补齐了 AGENTS 入口、execution plan、history、release note、CI/CD 和供应链安全骨架。 |
| 2026-04-21 | sandbox runtime | 提供首个可运行的 Go/Cobra sandbox-local CLI 与 SDK 骨架。 | 新增 macOS Seatbelt、Linux bubblewrap 最小后端，Windows capability 诊断，policy 示例、单元测试和 Apache-2.0 许可。 |
| 2026-04-21 | sandbox runtime | 支持 macOS/Linux 的网络 allowlist，并产出真实跨平台 CLI 归档。 | 新增 host-managed HTTP/HTTPS proxy、Linux UDS bridge + seccomp wrapper，并把 release 打包切换为 darwin/linux/windows arm64/amd64 二进制。 |
| 2026-04-21 | sandbox runtime | Windows 后端从 noop smoke 推进到真实本机策略实现，并暴露当前启动兼容性风险。 | 新增 Windows local-user 后端，支持 ACL 文件读写策略、Job Object 进程树清理、offline/open 网络模式；UTM Windows arm64 复验发现备用凭据启动部分系统程序会返回 `0xC0000142`，已记录为后续阻塞。 |
| 2026-04-22 | sandbox runtime | Windows 后端避开 UTM/SSH service 下备用凭据直启 `0xC0000142`，恢复真实 E2E。 | Windows runner 改为持久 disabled `sandboxlocal` identity + 一次性 Scheduled Task；验证 ACL read/write deny、offline/open 网络和 cleanup，无新增 `sbx*` 临时用户。 |
