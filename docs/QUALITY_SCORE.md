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
| 产品面 | D | 还没有真实产品定义。 | 先明确第一个用户路径和验收标准。 |
| 架构文档 | B | 已替换为 Go sandbox runtime 的真实顶层架构，并补充设计文档、active plan 和三端后端状态。 | 后续随 SDK API 稳定、Windows allowlist 和 CI 矩阵继续同步。 |
| 测试 | C | 已接入 Go 单元测试、CLI smoke、macOS/Linux allowlist 与文件隔离验证；Windows local-user/ACL/firewall 已通过持久 disabled identity + Scheduled Task runner 解决 UTM arm64 `0xC0000142` 启动阻塞，但三端 E2E 还主要是手工命令。 | 把三端 E2E 固化进 CI 矩阵，并补 Windows setup/cleanup、symlink/junction、IP canonicalization、cleanup 异常路径测试。 |
| 可观测性 | D | 还没有日志、指标、链路的约定。 | 明确本地和 CI 怎么访问观测数据。 |
| 安全 | C | 默认约束已经有了，但具体实现还没落地。 | 根据项目接入真实认证、密钥和依赖治理。 |
