## [2026-09-18 16:00] | Task: 强化 Windows write allow-list

### 🤖 Execution Context

- **Agent ID**: TraeCode
- **Base Model**: GPT-5
- **Runtime**: TraeCode CLI

### 📥 User Query

> 将 Windows sandbox 修复沉淀回上游项目，供 `device-executor` 直接依赖，不在业务仓复制维护。

### 🛠 Changes Overview

**Scope:** Windows backend、helper protocol、engine cleanup、SDK capability error、测试与文档

**Key Actions:**

- **严格写入 allow-list**: 每次运行创建随机 capability SID，实际命令使用 capability + runner + logon + Everyone restricting SIDs 的 `WRITE_RESTRICTED` token；排除内置 Users 组，ACL grant 同时面向 runner 账户与 capability SID。
- **修正只读行为**: write deny 仅拒绝数据修改和权限变更位，不再因 `FILE_GENERIC_WRITE` 中的共享标准位误伤读取。
- **可靠 cleanup**: 运行上下文取消后，ACL、scheduled task、防火墙规则和 runner 禁用仍用 detached context 清理。
- **错误可见性**: SDK `Check` 不再吞掉 backend capability error，同时保留 capability report。

### 🧠 Design Intent (Why)

仅给 runner 账户添加 write grant 不能阻止它继承宿主 ACL 的写权限。Windows restricted token 会对普通 token 与 restricting SID 做两次访问检查；每次随机 capability SID 只出现在显式 write-allow 路径上。restricting-SID 集合额外保留 runner account、当前 logon SID 和 Everyone，让系统程序能使用 profile/session/普通 runtime objects，但不加入内置 Users 组；外部公共目录写入仍由真机回归证明被拒绝。保留固定 runner 是为了避免 Scheduled Task 加载每次新建账户的 profile 后留下无法即时卸载的 profile hive。

### 📁 Files Modified

- `internal/backend/windows/account_windows.go`
- `internal/backend/windows/backend.go`
- `internal/backend/windows/backend_test.go`
- `internal/winrunner/runner_windows.go`
- `internal/engine/manager.go`
- `pkg/sandbox/types.go`
- `docs/ARCHITECTURE.md`
- `docs/design-docs/go-sandbox-runtime-architecture.md`
- `docs/SANDBOX_SECURITY_SCENARIOS.md`
