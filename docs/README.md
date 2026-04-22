# Aether Hyperion 文档中心

本文档库为 Aether Hyperion 架构的官方工程依据。为解决早期文档发散、重叠的问题，已重新整合成 5 份具备清晰边界的核心标准文档。

## 目录与阅读路径

| 文档名称 | 核心主题 | 适用对象 |
|---------|---------|---------|
|[**01_ARCHITECTURE_AND_VISION.md**](01_ARCHITECTURE_AND_VISION.md) | **架构与愿景**：阐述降维执行矩阵、Hypercore 职责、多态隔离域机制、物理强制隔离的安全模型及高级韧性（状态迁移/硬件降级）。 | 架构师、新加入的开发者、安全研究员 |
|[**02_SUBSYSTEMS_AND_ECOSYSTEM.md**](02_SUBSYSTEMS_AND_ECOSYSTEM.md) | **子系统与生态**：深度解析 MMDL（去重账本）、Aether Fusion 机制、融合渲染架构，以及如何基于本架构开发操作系统发行版。 | 系统服务开发者、UI/桌面环境开发者 |
| [**03_HYPERCALL_ABI_SPEC.md**](03_HYPERCALL_ABI_SPEC.md) | **接口规范**：Guest 与 Hypervisor 通信的唯一合法约定。包含寄存器规则、完整 Hypercall 号定义、MSB 原子转移算法及 VM-Exit 拦截行为。 | 底层内核开发者、驱动及隔离域开发者 |
|[**04_ENGINEERING_AND_CONTRIBUTING.md**](04_ENGINEERING_AND_CONTRIBUTING.md) | **工程与贡献**：项目治理（TSC/RFC 机制）、极简开发规范（`no_std` / unsafe 边界）、代码树结构及开发任务分解 (WBS)。 | 核心代码贡献者、测试工程师 |
|[**05_STATUS_AND_ROADMAP.md**](05_STATUS_AND_ROADMAP.md) | **状态与路线图**：本仓库当前确切的实现勾选进度、已知技术债务，以及涵盖阶段 I 到阶段 VIII 的长期产品战略部署计划。 | 项目管理者、所有开发者 |

## 文档维护原则

1.  **唯一事实来源**：底层 API 变更必须同步至 `03_HYPERCALL_ABI_SPEC.md`。
2.  **进度解耦**：战略愿景目标与本仓库当前代码实现的勾选状态严格隔离，所有关于“目前代码做到了哪一步”的依据均以 `05_STATUS_AND_ROADMAP.md` 为准。
3.  **克制与收敛**：新增文档需经过技术指导委员会 (TSC) 评估，避免理论文档无序扩张。最佳的底层细节说明是代码本身。
