# CI 说明

这个仓库当前只保留基础 CI，不再维护占位 release、部署或供应链扫描流水线。

## 默认包含的内容

- `ci.yml`：仓库级检查，覆盖 docs、repo hygiene、GitHub Action pinning、shell 脚本语法、Go 单元测试和 Markdown lint。
- `scripts/ci.sh`：本地和 GitHub Actions 共用的验证入口。
- `scripts/check-repo-hygiene.sh`：检查仓库协作所需的基础文件是否还在。
- `scripts/check-action-pinning.sh`：检查 workflow 里的 `uses:` 是否固定到不可变 commit SHA。

## 设计原则

当前目标是守住仓库可读性和基础可验证性。没有真实发布需求前，不保留会误导 Agent 或评审者的占位 CD 流程。

如果后续要重新接入 release 或部署流程，先明确产物、触发条件、权限和验收方式，再新增 workflow 和脚本。

所有 GitHub Actions 都已经 pin 到 commit SHA。后续升级 action 时，也要继续保持这个约束。

## 推荐接入顺序

1. 保留 `ci.yml`，作为唯一默认常驻的仓库基础门禁。
2. 在 `scripts/ci.sh` 里继续叠加项目自己的验证命令；当前 Go 项目会在存在 `go.mod` 时运行 `go test ./...`。
3. 需要跨平台 E2E 时，先确认 runner 能力和 skip/fail 策略，再放进 CI 矩阵。
4. 需要 release 时，新建明确产物目录、manifest、签名或 provenance 约定。
5. 需要供应链扫描时，选择能在当前仓库权限和依赖形态下稳定运行的工具。
