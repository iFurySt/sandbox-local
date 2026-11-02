# Windows 管理员后端 mutex 所有权修复

## 目标与范围

修复成功执行命令后，Windows 管理员后端 cleanup 因 OS 线程切换返回锁所有权错误的问题。
保留原有命名 mutex、ACL、账户与网络策略，不修改 AppContainer 或其他平台后端。

## 验证步骤

- 在 Windows 真机用强制跨线程 cleanup 的回归测试确认旧实现稳定失败。
- 将 mutex 获取和释放固定到同一所有者线程，验证串行化、重复释放和异常路径。
- 执行本地 `make ci`、Go race 检查和 Windows 原生测试；回读 PR checks。

## 风险与约束

mutex 属于 OS 线程而非 Go goroutine。修复必须允许 cleanup 从其他线程调用，
且释放与关闭句柄后才能向调用方报告完成；不得通过吞掉错误让命令变成成功。

## 进度

- Windows 原实现的确定性跨线程 cleanup 回归连续 10 次失败。
- 修复后四组原生锁回归各重复 100 次，400 次通过；本地 CI、race、Windows vet 和交叉编译通过。
- CLI setup 和一轮 echo（含 cleanup）通过；后续执行被 Windows Defender 阻止，完整 CLI 回归留作验证缺口。
- 新增 Windows CI 原生锁回归；PR 状态与 checks 以 GitHub 为准。
