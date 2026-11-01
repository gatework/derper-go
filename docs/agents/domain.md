# Domain docs

本仓库采用单项目领域文档布局。

## 探索前读取

- 根目录 GLOSSARY.md：已确认的领域术语。
- docs/adr/：读取与当前改动有关的架构决策。
- 既有 README.md、docs/DESIGN.md、docs/CONFIGURATION.md 与 docs/DEPLOYMENT.md 提供当前实现和部署背景。

GLOSSARY.md 或 docs/adr/ 尚不存在时直接继续工作，不提示缺失，不提前生成空文件。domain-modeling 在术语或决策实际明确时按需创建；本次初始化只记录路径。

## 命名与决策

代码、测试、工单与报告中的领域名称遵循 GLOSSARY.md，避免无理由引入同义词。术语确有缺口时留给 domain-modeling 处理。

当前领域围绕中继、准入、证书续期、DNS 发布、部署和重载展开；最终词汇以已确认的领域文档为准。

与既有 ADR 冲突时明确指出冲突及重新讨论的理由，不静默覆盖。无需 GLOSSARY-MAP.md 或每模块一套领域上下文。
