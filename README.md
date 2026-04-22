# Aether Kernel (Hyperion Architecture)

Aether Kernel 是一个基于硬件虚拟化指令集的**硬件隔离执行矩阵 (Hardware-Isolated Execution Matrix)**。它抛弃了传统的 Ring 0 / Ring 3 宏内核范式，将自身降维至处理器的最高硬件隔离层（Ring -1 / VMX Root），为从云原生服务器到通用桌面环境的计算连续体，提供全硬件隔离、零损耗的终极执行基底。

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE-APACHE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)

## 核心架构特性

*   **Hypercore 矩阵**：运行在 VMX Root 模式下的极简调度器，仅负责 CPU 周期分配、物理页框路由（EPT）与 IOMMU 域划分。支持形式化验证。
*   **多态隔离域 (Enclaves)**：应用、系统服务及闭源驱动均运行在独立的、由嵌套页表强制隔离的微型虚拟机中，免疫跨域侧信道攻击。
*   **内存语义总线 (MSB)**：通过修改 EPT 实现物理内存所有权的原子化转移，提供跨域绝对零拷贝的进程间通信。
*   **内存映射去重账本 (MMDL)**：基于硬件写时复制与 EPT 重定向的全局内存去重及原生持久化机制。
*   **Aether Fusion**：在无需修改存量代码的前提下，为完整 Linux 宏域注入底层高性能硬件与网络直通能力。

## 快速入门

### 编译工具链与环境要求
*   Rust Nightly 工具链 (`x86_64-unknown-none` target)
*   构建依赖：`gcc`, `ld`, `objcopy`, `grub-mkrescue`
*   运行依赖：QEMU (`qemu-system-x86_64`) 并建议启用 KVM 与嵌套虚拟化 (Nested VMX)。

### 编译与启动

本系统使用 Cargo Workspace 管理内核与初始隔离域镜像。

```bash
# 1. 构建所有组件 (Hypercore + Init Domain + Macro Domain)
cargo build --workspace --target x86_64-unknown-none --release

# 2. 编译并提取 Guest 隔离域扁平二进制文件
./scripts/build-guest.sh
make macro

# 3. 构建可引导的 ISO 镜像 (包含 Multiboot2 引导链)
make iso

# 4. 在 QEMU 中运行 (默认优先尝试 KVM)
make run
```

*若需强制开启/关闭嵌套虚拟化，可执行 `make run-kvm` 或直接通过 `./scripts/run-qemu.sh` 调试串口输出。*

## 文档指引

详尽的架构理论、ABI 规范及工程进度已整合至 `docs/` 目录。请从 **[文档中心 (docs/README.md)](docs/README.md)** 开始阅读。

*   架构愿景与安全模型：`01_ARCHITECTURE_AND_VISION.md`
*   子系统与生态发行版指南：`02_SUBSYSTEMS_AND_ECOSYSTEM.md`
*   Hypercall ABI 与总线规范：`03_HYPERCALL_ABI_SPEC.md`
*   工程规范与开源贡献：`04_ENGINEERING_AND_CONTRIBUTING.md`
*   当前状态与战略路线图：`05_STATUS_AND_ROADMAP.md`

## 许可证

本项目在 MIT 许可证和 Apache 许可证（版本 2.0）下双重许可。详情参见 `LICENSE-MIT` 与 `LICENSE-APACHE`。