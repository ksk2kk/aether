# 3. Hypercall ABI 与硬件总线规范

本文档定义 Guest 隔离域向 Hypercore 发起特权请求的唯一合法接口（Hypercall），以及内存语义总线 (MSB) 和 VM-Exit 的处理契约。

## 3.1 ABI 调用约定 (x86-64 System V 扩展)

Guest 必须在 VMX Non-Root 模式下使用 `VMCALL` 指令触发调用。
*   **寄存器映射**：
    *   `RCX`: 调用号 (0-255)
    *   `RDX`, `RSI`, `RDI`, `R8`, `R9`: 参数 1 至 5
*   **返回值**：
    *   `RAX`: 执行状态码（`0x00` 为成功，非零为错误码）
    *   `RBX`, `RCX`: 根据具体调用号用作附加返回数据载体。

**错误码定义**：
*   `0x00`: `HC_SUCCESS`
*   `0x01`: `HC_INVALID_CALL`
*   `0x02`: `HC_INVALID_ENCLAVE`
*   `0x03`: `HC_PERMISSION_DENIED`
*   `0x04`: `HC_RESOURCE_EXHAUSTED`
*   `0x05`: `HC_NOT_IMPLEMENTED`

## 3.2 官方 Hypercall 注册表

| 号码 | 名称 | 描述 | 参数 |
|---|---|---|---|
| `0x00` | `PageTransfer` | 单页 MSB 转移：在源/目标 EPT 间原子化转移 4KB 页的所有权 | a1: `src_id`, a2: `dst_id`, a3: `src_gpa`, a4: `EptFlags`, a5: `dst_gpa` |
| `0x01` | `InjectInterrupt` | 请求 APIC 向指定 Enclave 的向量表注入外部硬件中断 | a1: `target_enclave_id`, a2: `vector` |
| `0x02` | `QueryEnclave` | 探测目标 Enclave 状态 | a1: `enclave_id` (`0`=self)。返回状态码于 RAX，`RBX`=`EnclaveState` |
| `0x03` | `MapDevice` | 将 PCI BDF 所属的 MMIO 空间恒等映射至当前域，并通知 IOMMU 仲裁 | a1: `bdf` (16bit), a2: `mmio_gpa`, a3: `bytes` |
| `0x04` | `Yield` | 协作式调度：主动挂起当前执行流，唤醒就绪队列 | 无 |
| `0x06` | `GetHypervisorInfo`| 查询底层框架 API 级别 | 无。返回 `RBX` (高 32 位: 魔数 `AETH`, 低 32 位: API Level) |
| `0x07` | `PageTransferBatch`| 批量 MSB 转移：最多处理 32 页 | a1: `src_id`, a2: `dst_id`, a3: `list_gpa`, a4: `count` |
| `0x08` | `MmdlPublish` | 去重账本发布：提供内容 Hash，登记该物理页供其他域共享 | a1: `slot`, a2: `content_tag`, a3: `gpa`, a4: `is_huge` |
| `0x09` | `MmdlMapShared` | 将 MMDL 中发布的物理页以只读模式映射入目标域的 EPT | a1: `dst_id`, a2: `gpa`, a3: `slot` |
| `0x0A` | `Microbench` | 调试探针：执行空循环测定 TSC 损耗 | a1: `iterations` |
| `0x0B` | `FusionRegister` | Aether Fusion 桥接点注册：预定 Virtio 后端资源 | a1: `backend_kind`, a2: `service_id` (`0`=self) |
| `0x0C` | `FenceStress` | 并发压测：全局触发指定次数的 `INVEPT` 硬件屏障 | a1: `count` |
| `0x0D` | `QueryRealmCaps` | 探测自身执行维度与能力位图 | 无。返回 `RCX` (类型: Micro/Macro)，`RBX` (能力 Bitmap) |
| `0x0E` | `MapSharedReadOnly`| 源域授权目标域对其指定页的只读映射（非转移） | a1: `src_id`, a2: `dst_id`, a3: `gpa` |
| `0x0F` | `PageTransferAsync`| 结合中断的 MSB 转移：转移后触发目标域 APIC 异步事件 | a1: `src_id`, a2: `dst_id`, a3: `src_gpa`, a4: `flags`, a5: `dst_gpa` |
| `0x10` | `GetDmaAuditLog` | 从 IOMMU 取回硬件越权审核日志至目标物理页 | a1: `guest_buf_gpa`, a2: `len_bytes` |
| `0xFF` | `Debug` | 同步向宿主机串口输出格式化字符流 | a1: `msg_gpa`, a2: `len`。返回 `RAX`=`written_bytes` |

*开发自检口：`0x42`。子命令 1：通过串口打印 IOMMU Audit Ring；子命令 2：打印绑定矩阵。*

## 3.3 内存语义总线 (MSB) 原子性契约
MSB 旨在废除内存拷贝。执行 `0x00 PageTransfer` 时的硬件原子步骤：
1.  定位源 EPT 表。若指定的 GPA 未映射，立刻中止返回。
2.  执行 CAS 摘除源 EPT 项，确保当前物理页变为隔离游离态。
3.  更新目标 EPT 树，将该物理页映射至目标 GPA。
4.  执行 `mfence` 强制刷新全核心缓存线，并触发 `invept` 全局清空 TLB。
5.  控制权交还至硬件。此时数据在物理介质中未发生任何位移，但绝对所有权已交割。

## 3.4 VM-Exit 异常收敛处理
系统接管所有 `ExitReason`。
*   `18 (VMCALL)`：路由至 Hypercall 分发器。
*   `48 (EPT Violation)`：分析 `ExitQualification`。若为尝试写入 MMDL 账本管理的只读去重页，则分配新帧触发 COW；否则判定为恶意越权，终结执行域。
*   `01 (ExternalInterrupt)`：通过读取 `VmExitInterruptionInfo` 截取物理向量号，向源域发送 EOI 后，交由 APIC Manager 进行虚拟中断的二次注入。