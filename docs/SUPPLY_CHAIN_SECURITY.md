# 供应链安全

这份文档定义当前仓库默认采用的供应链安全做法。

## 默认控制项

- 所有 GitHub Actions 都固定到不可变的 commit SHA，而不是漂移的版本标签。
- 基础 CI 会运行 `scripts/check-action-pinning.sh`，避免 workflow action 引用退回浮动 tag。
- 当前没有自动 dependency review、OSV、SBOM 或 provenance workflow；这些能力等真实 release 和仓库权限明确后再接入。

## 当前对应关系

- `scripts/check-action-pinning.sh`：如果 workflow 里出现浮动 tag 而不是 SHA，直接让 CI 失败。

## 限制和前提

- Dependency Review 在 public repo 可以直接使用；private repo 通常需要 GitHub Advanced Security 或对应的代码安全能力。
- OSV 和 SBOM 的效果依赖仓库里存在可识别的依赖清单或 lockfile。
- Provenance 只有在 release workflow 产出真实、可分发制品时才有意义。
- OpenSSF Scorecard 默认不启用，因为仓库还没有真实分支保护、release 历史和 SAST 姿态可以评分；等仓库规则配置完成后再按需加回。

## 项目落地后建议继续做的事

- 锁定并提交项目真实依赖的 lockfile。
- 让构建过程尽量可重复、可验证。
- 重新接入 dependency review、OSV、SBOM 和 provenance 前，先确认这些 workflow 不会因为权限或占位产物长期失败。
- 如果条件允许，在部署链路里增加对 provenance 的校验。
- 把 attestation 校验继续下沉到部署平台或准入层。
