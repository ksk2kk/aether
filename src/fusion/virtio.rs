/* src/fusion/virtio.rs */
use x86_64::PhysAddr;
use crate::memory::ept::EptManager;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtioMsbDescriptor {
    pub gpa_address: u64,
    pub length: u32,
    pub flags: u16,
    pub next: u16,
}

pub struct VirtioMsbQueue {
    pub ring_gpa: PhysAddr,
    pub queue_size: u16,
    pub last_avail_idx: u16,
}

impl VirtioMsbQueue {
    pub const fn new(ring_gpa: PhysAddr, queue_size: u16) -> Self {
        Self {
            ring_gpa,
            queue_size,
            last_avail_idx: 0,
        }
    }

    pub fn process_tx_batch(
        &mut self,
        src_id: u32,
        dst_id: u32,
        _src_ept: &mut EptManager,
        _dst_ept: &mut EptManager,
    ) -> usize {
        crate::log_debug!("处理 VirtIO MSB 发送队列: 源={}, 目标={}", src_id, dst_id);
        0
    }
}