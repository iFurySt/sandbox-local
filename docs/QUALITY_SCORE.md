# 质量评分

用这份文档按产品区域和架构层次记录当前质量水位，方便持续知道最薄弱的地方在哪。

## 建议的评分标准

- `A`：覆盖完整、行为稳定、文档清楚、运行风险低。
- `B`：整体可接受，但还有明确短板。
- `C`：能用，但需要针对性补强。
- `D`：脆弱、缺少规范，或很多行为尚未定义。

## 初始模板

| 区域 | 评分 | 原因 | 下一步 |
| --- | --- | --- | --- |
| 产品面 | C | 已明确首个 Go SDK 用户路径：使用方 import `pkg/sandbox`，在自身 `main()` 顶部调用 `sandbox.MaybeRunHelper()`，并通过 `HelperPath: os.Args[0]` 复用自身二进制作为 helper；`examples/quickstart` 已提供可复制的独立 Go module。 | 继续补版本化 release、安装/升级说明和更完整的 SDK API 稳定性约定。 |
| 架构文档 | B | 已替换为 Go sandbox runtime 的真实顶层架构，并补充设计文档、active plan、SDK helper 约定、Windows setup/allowlist 和三端后端状态；CI/CD 文档已收口为当前实际保留的基础 CI。 | 后续随 SDK API 稳定、CI 矩阵、真实 release、SBOM/provenance 和安装脚本继续同步。 |
| 测试 | B | 已接入 Go 单元测试、CLI smoke、macOS/Linux/Windows 三端 SDK E2E；E2E 通过 SDK 构建 helper binary，验证文件写 allow、`.git` 写 deny、read deny、offline、allowlist 允许/拒绝和直连绕过阻断；已新增安全场景手册，便于继续演化为 case-driven E2E。 | 把三端 E2E 固化进 CI 矩阵，并补 junction、glob、IP canonicalization、Windows loopback 细分策略、cleanup 异常路径测试。 |
| 可观测性 | D | 还没有日志、指标、链路的约定。 | 明确本地和 CI 怎么访问观测数据。 |
| 安全 | B | 三端已有 OS-native enforcement 闭环；路径会 canonicalize 现有 symlink 前缀，macOS read/write deny、Linux seccomp bridge、Windows ACL/firewall allowlist 均有 E2E 覆盖；`docs/SANDBOX_SECURITY_SCENARIOS.md` 已把实际可覆盖场景整理成三端 step-by-step case。 | 继续补 junction、loopback 本地服务边界、IP/IDNA canonicalization、密钥目录默认保护和供应链治理。 |
