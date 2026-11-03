# 可选 Seatbelt 默认策略

## 用户诉求

提供可选的 macOS Seatbelt 基线配置，默认行为不变，让上层应用显式启用默认允许的 OS 操作策略。

## 变更

- SDK Policy、YAML profile 和 CLI 映射支持 seatbelt.default_action，接受 deny/allow，空值保持 deny。
- macOS allow 模式显式保留文件读写与网络限制；未知值返回错误。
- 增加真实信号测试、默认兼容性与配置透传测试，两种模式均运行 SDK 文件/网络隔离测试。
- 修正 SDK 测试内容泄漏断言：使用不与文件名相同的标记，保留读取输出以检测真实泄漏。

## 取舍

allow 不是仅 signal 的授权，也不提供进程隔离；仍受宿主用户权限与系统限制约束。Linux/Windows 执行不变。
