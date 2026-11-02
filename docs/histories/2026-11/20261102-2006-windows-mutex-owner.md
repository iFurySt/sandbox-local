# Windows 管理员后端 mutex 所有权修复

## 诉求与执行上下文

用户要求在确认 Windows 锁释放错误能够重复复现后，修复并提交 PR。
由 Codex 在 macOS 构建，并在 Windows 10 amd64 原生环境验证。

## 改动

- `internal/backend/windows/setup_lock_windows.go`：专用 goroutine 固定 OS 线程，
  获取和释放原命名 mutex；允许调用方跨线程或重复关闭，保留错误返回。
- `internal/backend/windows/backend.go`：setup 与 cleanup 使用锁所有者，
  凭据初始化失败时也先释放锁再返回错误。
- `internal/backend/windows/setup_lock_windows_test.go`：覆盖跨线程 cleanup、
  已有持有者互斥、并发重复关闭和不同类型命名对象冲突。
- 更新架构说明和功能发布记录。
- 在 Windows CI 运行锁回归，避免平台 build tags 将测试排除在 Linux 检查外。

## 原因与验证

Windows mutex 的所有者是 OS 线程，Go goroutine 迁移后不能直接释放原线程持有的 mutex。
确定性回归测试在原实现在 Windows 上连续 10 次失败，返回相同的锁所有权错误；
修复后的四组回归各重复 100 次，共 400 次通过。

本地 `make ci`、`go test -race ./...`、Windows amd64 vet 和 ARM64 交叉编译通过。
Windows 原生 CLI 的 setup 和一轮 echo 命令（包括 cleanup）通过；
后续启动被测试机 Windows Defender 拦截，完整 CLI 回归未完成。
本次不修改 AppContainer、macOS 或 Linux 后端，也不将其他平台的超时归为同一原因。
