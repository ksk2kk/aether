/* src/mmdl/mod.rs */
use crate::memory::ept::{EptFlags, EptManager};
use spin::Mutex;
use x86_64::PhysAddr;
extern crate alloc;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use lazy_static::lazy_static; // 引入 lazy_static!

pub const SLOT_COUNT: usize = 16;

#[derive(Debug, Clone, Copy)]
pub struct MmdlSlot {
    pub content_tag: u64,
    pub hpa: PhysAddr,
    pub is_huge: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct NVMeCommandContext {
    pub opcode: u8,
    pub nsid: u32,
    pub prp1: u64,
    pub prp2: u64,
}

struct GlobalPageLedger {
    hash_to_page: BTreeMap<u64, (PhysAddr, usize)>,
}

impl GlobalPageLedger {
    fn new() -> Self {
        Self {
            hash_to_page: BTreeMap::new(),
        }
    }
}

lazy_static! { // 使用 lazy_static! 延迟初始化
    static ref GLOBAL_PAGE_LEDGER: Mutex<GlobalPageLedger> = Mutex::new(GlobalPageLedger::new());
}

pub struct MmdlLedger {
    slots: [Option<MmdlSlot>; SLOT_COUNT],
    nvme_context:[Option<NVMeCommandContext>; 8],
}

impl MmdlLedger {
    pub const fn new() -> Self {
        const EMPTY: Option<MmdlSlot> = None;
        const EMPTY_NVME: Option<NVMeCommandContext> = None;
        Self {
            slots:[EMPTY; SLOT_COUNT],
            nvme_context: [EMPTY_NVME; 8],
        }
    }

    pub fn publish(&mut self, index: usize, tag: u64, hpa: PhysAddr, is_huge: bool) -> Result<(), ()> {
        if index >= SLOT_COUNT {
            return Err(());
        }

        let mut ledger = GLOBAL_PAGE_LEDGER.lock();
        if let Some((_existing_hpa, ref_count)) = ledger.hash_to_page.get_mut(&tag) {
            *ref_count += 1;
        } else {
            ledger.hash_to_page.insert(tag, (hpa, 1));
        }

        self.slots[index] = Some(MmdlSlot {
            content_tag: tag,
            hpa,
            is_huge,
        });
        Ok(())
    }

    pub fn slot_frame(&self, index: usize) -> Option<(PhysAddr, bool)> {
        if index >= SLOT_COUNT {
            return None;
        }
        self.slots[index].map(|s| (s.hpa, s.is_huge))
    }

    pub fn map_shared_readonly(
        &self,
        dst_ept: &mut EptManager,
        index: usize,
        gpa: PhysAddr,
    ) -> Result<(), ()> {
        let (hpa, is_huge) = self.slot_frame(index).ok_or(())?;
        let flags = EptFlags::READ | EptFlags::MEMORY_TYPE_WB;
        if is_huge {
            dst_ept.map_2m(gpa, hpa, flags);
        } else {
            dst_ept.map(gpa, hpa, flags);
        }
        Ok(())
    }

    pub fn handle_cow_fault(&mut self, gpa: PhysAddr, ept: &mut EptManager, vpid: u16) -> bool {
        let hpa_opt = ept.translate_gpa(gpa);
        let Some(hpa) = hpa_opt else { return false };
        
        let mut is_cow = false;
        let mut is_huge = false;
        for slot in &self.slots {
            if let Some(s) = slot {
                if s.hpa == hpa {
                    is_cow = true;
                    is_huge = s.is_huge;
                    break;
                }
            }
        }
        if !is_cow { return false; }
        
        let flags = EptFlags::READ | EptFlags::WRITE | EptFlags::EXECUTE | EptFlags::MEMORY_TYPE_WB;
        
        if is_huge {
            let new_frame_opt = crate::memory::allocate_frame(); 
            let Some(new_frame) = new_frame_opt else { return false };
            let new_hpa = new_frame.start_address();
            unsafe {
                let src = crate::memory::phys_to_virt(hpa).as_ptr::<u8>();
                let dst = crate::memory::phys_to_virt(new_hpa).as_mut_ptr::<u8>();
                core::ptr::copy_nonoverlapping(src, dst, 4096);
            }
            ept.map(PhysAddr::new(gpa.as_u64() & !0xFFF), new_hpa, flags);
        } else {
            let new_frame_opt = crate::memory::allocate_frame();
            let Some(new_frame) = new_frame_opt else { return false };
            let new_hpa = new_frame.start_address();
            
            unsafe {
                let src = crate::memory::phys_to_virt(hpa).as_ptr::<u8>();
                let dst = crate::memory::phys_to_virt(new_hpa).as_mut_ptr::<u8>();
                core::ptr::copy_nonoverlapping(src, dst, 4096);
            }
            ept.map(PhysAddr::new(gpa.as_u64() & !0xFFF), new_hpa, flags);
        }
        
        crate::coherence::fence_and_invalidate_vpid(vpid);
        
        crate::log_debug!("MMDL 处理 COW: GPA {:#x} 重定向", gpa.as_u64());
        true
    }

    pub fn submit_nvme_command(&mut self, ctx: NVMeCommandContext) -> bool {
        for slot in self.nvme_context.iter_mut() {
            if slot.is_none() {
                *slot = Some(ctx);
                crate::log_debug!("NVMe 硬件加速指令已加入处理队列");
                return true;
            }
        }
        false
    }

    pub fn trigger_pml_snapshot(&self, pml_buffer_hpa: PhysAddr) -> Vec<u64> {
        let pml_virt = crate::memory::phys_to_virt(pml_buffer_hpa);
        let mut dirtied_gpas = Vec::new();
        if pml_virt.is_null() {
            return dirtied_gpas;
        }

        let pml_slice = unsafe { core::slice::from_raw_parts(pml_virt.as_ptr::<u64>(), 512) };

        for i in 0..512 {
            if pml_slice[i] != 0 {
                for bit in 0..64 {
                    if (pml_slice[i] >> bit) & 1 == 1 {
                        let gpa = ((i * 64 + bit) as u64) * 4096;
                        dirtied_gpas.push(gpa);
                    }
                }
            }
        }
        
        crate::log_debug!("PML 快照分析完成，共产生 {} 个脏页", dirtied_gpas.len());
        dirtied_gpas
    }
}

static LEDGER: Mutex<MmdlLedger> = Mutex::new(MmdlLedger::new());

pub fn init() {
    crate::log_info!("内存映射去重账本 (MMDL) 初始化完毕 (容量: {} 槽位，附带硬件卸载列阵与大页支持)", SLOT_COUNT);
}

pub fn ledger() -> spin::MutexGuard<'static, MmdlLedger> {
    LEDGER.lock()
}