# 5. 当前实现状态与产品战略路线图

本文档区分工程当前的客观开发节点，以及基于该基底延伸的产品演进战略。是项目工程进度的唯一官方对齐依据。

## 5.1 当前实现基线与状态清单
*时间基准：2026.04*

### 已贯通工程节点
*   [x] **基础设施**：`x86_64-unknown-none` 目标编译，无隐藏 `unsafe`。
*   [x] **硬件掌管**：Bootloader 移交，多阶引导验证器 (BootValidator) 无错通过。
*   [x] **CPU 虚拟化**：成功载入 VMCS，启动 VMX Root 模式。VM-Exit 总线级拦截全面运行。
*[x] **隔离拓扑**：内存基于 Buddy Allocator 及 EPT 物理强制切分；IOMMU VT-d 审计环就绪，通过 `HypercallMapDevice` 支持硬件级 DMA 阻断。
*[x] **内存语义总线 (MSB)**：完成基于 `0x00 PageTransfer` 及 `0x07 PageTransferBatch` 的原子所有权交割，结合 `INVEPT` 提供绝对隔离域间通讯。
*   [x] **扩展服务桩**：MMDL 去重账本底层 API (`0x08`, `0x09`) 及 Fusion 注册 (`0x0B`) 部署完毕。
*[x] **首个生态点**：Init Domain（极简微域）及 Macro Domain 样板，使用独立 `link.x` 及自动构建链编译扁平二进制，顺利经由 Hypercore 并发拉起调度。

### 遗留技术债务与短期演进
*   **多核环境扩容**：当前调度围绕核心 0 及协同让出展开，虽储备了 x2APIC 及 IPI 能力，完全的多核硬抢占并发调度流尚未闭环。
*   **真实硬件验证集**：目前基于 QEMU KVM/Nested-VMX 测试，需导入物理 NVMe 存储及显卡的裸机直通长周期 Soak 压测。

## 5.2 长期产品战略部署阶段 (Strategic Roadmap)

从当前的“实验性微架构实现”，向最终替代 Linux 的生态基石进发，战略分阶如下：

*   **阶段 I ~ IV：硬件基底与原语证明**
    实现核心 Hypervisor，利用 EPT 提供内存强制隔离，并基于 MSB 实现零拷贝数据通信。（*本仓库目前处于该周期的收尾状态*）。
*   **阶段 V：宏域兼容性突破 (Macro-Realm Posix)**
    实现标准的 qcow2 或 raw 镜像加载，拉起高度精简的 Linux 模拟内核，使完整的 Debian/Alpine 能够稳定运行在微架构域内。
*   **阶段 VI：Fusion 引擎全速启动**
    为宏域开发标准的 `eth-fusion` / `blk-fusion` 虚拟挂载驱动；验证无改动的存量应用程序经由宏域的 MSB 通道，在吞吐量与时延上完全吊打传统 Linux 物理机。
*   **阶段 VII：MMDL 数据化革命**
    摒弃传统文件系统，确立全局内容哈希系统。利用底层写时复制，实现万个容器共享同一物理内存的启动奇迹。
*   **阶段 VIII：生态接管与开发者平台**
    发布成熟的 Hyperion-Pilot SDK；推动基于 Aether 架构的第一代空间计算平台或桌面 OS 发行版走向商用。