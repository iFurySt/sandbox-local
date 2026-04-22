# 安全默认约束

这份文档用于把安全默认值讲清楚，避免实现逐步演进时越走越散。

建议维护的内容：

- 认证与授权约束。
- 密钥和环境变量管理方式。
- 依赖治理与供应链安全要求。
- 数据分级、脱敏与保留策略。
- 对外 API、Webhook、文件上传和沙箱执行的规则。

仓库级的依赖、SBOM 和 provenance 默认能力，统一写在 `docs/SUPPLY_CHAIN_SECURITY.md`。

本地 sandbox runtime 已覆盖的安全场景、三端手工复验步骤和可演化为 E2E 的断言，见 `docs/SANDBOX_SECURITY_SCENARIOS.md`。
