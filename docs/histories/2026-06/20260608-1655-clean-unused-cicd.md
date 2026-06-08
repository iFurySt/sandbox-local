## [2026-06-08 16:55] | Task: clean unused cicd

### Execution Context

- **Agent ID**: `Codex`
- **Base Model**: `GPT-5`
- **Runtime**: `local CLI`

### User Query

> 清理掉无用的cicd

### Changes Overview

**Scope:** repository workflow and docs

**Key Actions:**

- **Removed unused workflows**: 删除未接入真实发布价值且配置已不一致的 release workflow、供应链扫描 workflow 和 dependency review 配置。
- **Pruned release script**: 删除不再由 workflow 或 Makefile 使用的 `scripts/release-package.sh`，并移除 `make release-package`。
- **Synced docs**: 更新 CI/CD、供应链安全、架构、active plan、协作和质量评分文档，明确当前只保留基础 CI。

### Design Intent (Why)

占位 CD 和供应链流水线会让 Agent 误判仓库已经具备 release、SBOM 和 provenance 能力；其中 release workflow 还引用了脚本不会产出的 `dist/repo-metadata.tgz`。收口到基础 CI 后，仓库流程与实际可验证能力一致，后续 release 需求明确时再重新接入。

### Files Modified

- `.github/workflows/release.yml`
- `.github/workflows/supply-chain-security.yml`
- `.github/dependency-review-config.yml`
- `scripts/release-package.sh`
- `Makefile`
- `scripts/check-repo-hygiene.sh`
- `docs/CICD.md`
- `docs/SUPPLY_CHAIN_SECURITY.md`
- `docs/REPO_COLLAB_GUIDE.md`
- `docs/ARCHITECTURE.md`
- `docs/design-docs/go-sandbox-runtime-architecture.md`
- `docs/exec-plans/active/go-sandbox-runtime.md`
- `docs/QUALITY_SCORE.md`
- `AGENTS.md`
