// src/arch/x86_64/iommu/tables.rs
use x86_64::{PhysAddr, structures::paging::{PhysFrame, Size4KiB}};

pub const PAGE_SIZE: u64 = 4096;
pub const PT_LEVEL_ENTRIES: usize = 512;

pub struct HardwareTables {
    pub root_table_addr: Option<PhysAddr>,
    pub context_table_addr: Option<PhysAddr>,
    pub bus_context_tables:[Option<PhysAddr>; 256],
}

impl HardwareTables {
    pub const fn new() -> Self {
        Self {
            root_table_addr: None,
            context_table_addr: None,
            bus_context_tables: [None; 256],
        }
    }

    pub fn initialize_root_context_table(&mut self) -> bool {
        let root = match crate::memory::allocate_frame() {
            Some(f) => f.start_address(),
            None => {
                crate::log_error!("为控制层映射构建基底失败：未获得可用物理页作为总根表");
                return false;
            }
        };
        let ctx = match crate::memory::allocate_frame() {
            Some(f) => f.start_address(),
            None => {
                crate::log_error!("下联级映射资源缺失：缺乏用作上下文表的内存资源");
                return false;
            }
        };

        unsafe {
            let rv = crate::memory::phys_to_virt(root);
            let cv = crate::memory::phys_to_virt(ctx);
            if !rv.is_null() {
                core::ptr::write_bytes(rv.as_mut_ptr::<u8>(), 0, 4096);
            }
            if !cv.is_null() {
                core::ptr::write_bytes(cv.as_mut_ptr::<u8>(), 0, 4096);
            }

            if !rv.is_null() {
                let re = rv.as_mut_ptr::<u64>();
                let bus0_entry = 1u64 | (ctx.as_u64() & !0xFFF);
                core::ptr::write_volatile(re, bus0_entry);
            }
        }

        self.root_table_addr = Some(root);
        self.context_table_addr = Some(ctx);
        self.bus_context_tables[0] = Some(ctx);

        crate::log_debug!("初始化总线基板记录组: 根映射至 {:#x}, 总线 0 映射至 {:#x}", root.as_u64(), ctx.as_u64());
        true
    }

    pub fn ensure_context_table_for_bus(&mut self, bus: u8) -> Option<PhysAddr> {
        if let Some(existing) = self.bus_context_tables[bus as usize] {
            return Some(existing);
        }

        let ctx = match crate::memory::allocate_frame() {
            Some(f) => f.start_address(),
            None => {
                crate::log_error!("节点资源不足导致结构受损：无法承载针对总线 {} 的表单创建", bus);
                return None;
            }
        };

        unsafe {
            let cv = crate::memory::phys_to_virt(ctx);
            if !cv.is_null() {
                core::ptr::write_bytes(cv.as_mut_ptr::<u8>(), 0, 4096);
            } else {
                return None;
            }
        }

        let root = self.root_table_addr?;
        let root_virt = crate::memory::phys_to_virt(root);
        if root_virt.is_null() {
            return None;
        }

        unsafe {
            let root_entries = root_virt.as_mut_ptr::<u64>();
            let bus_entry = 1u64 | (ctx.as_u64() & !0xFFF);
            core::ptr::write_volatile(root_entries.add(bus as usize), bus_entry);
        }
        self.bus_context_tables[bus as usize] = Some(ctx);

        crate::log_debug!("完成系统结构扩建: 承载关联链路已对接到总线 {}", bus);

        Some(ctx)
    }

    pub fn alloc_zeroed_page_table() -> Option<PhysAddr> {
        let frame = crate::memory::allocate_frame()?;
        let phys = frame.start_address();
        let virt = crate::memory::phys_to_virt(phys);
        if virt.is_null() {
            return None;
        }
        unsafe {
            core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, PAGE_SIZE as usize);
        }
        Some(phys)
    }

    pub fn get_or_alloc_next_level(table_phys: PhysAddr, index: usize) -> Option<PhysAddr> {
        if index >= PT_LEVEL_ENTRIES {
            return None;
        }
        let table_virt = crate::memory::phys_to_virt(table_phys);
        if table_virt.is_null() {
            return None;
        }

        unsafe {
            let entry_ptr = table_virt.as_mut_ptr::<u64>().add(index);
            let curr = core::ptr::read_volatile(entry_ptr);
            if (curr & 1) != 0 {
                return Some(PhysAddr::new(curr & !0xFFF));
            }

            let next = Self::alloc_zeroed_page_table()?;
            core::ptr::write_volatile(entry_ptr, (next.as_u64() & !0xFFF) | 0b11);
            Some(next)
        }
    }

    pub fn map_slpt_page(root_phys: PhysAddr, iova: PhysAddr, hpa: PhysAddr) -> bool {
        let iova_u64 = iova.as_u64();
        let pml4_idx = ((iova_u64 >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((iova_u64 >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova_u64 >> 21) & 0x1FF) as usize;
        let pt_idx = ((iova_u64 >> 12) & 0x1FF) as usize;

        let Some(pdpt) = Self::get_or_alloc_next_level(root_phys, pml4_idx) else { return false; };
        let Some(pd) = Self::get_or_alloc_next_level(pdpt, pdpt_idx) else { return false; };
        let Some(pt) = Self::get_or_alloc_next_level(pd, pd_idx) else { return false; };

        let pt_virt = crate::memory::phys_to_virt(pt);
        if pt_virt.is_null() {
            return false;
        }
        unsafe {
            let pte = pt_virt.as_mut_ptr::<u64>().add(pt_idx);
            let hpa_page = hpa.as_u64() & !0xFFF;
            core::ptr::write_volatile(pte, hpa_page | 0b11);
        }
        true
    }

    pub fn get_next_level(table_phys: PhysAddr, index: usize) -> Option<PhysAddr> {
        if index >= PT_LEVEL_ENTRIES {
            return None;
        }
        let table_virt = crate::memory::phys_to_virt(table_phys);
        if table_virt.is_null() {
            return None;
        }
        unsafe {
            let entry_ptr = table_virt.as_mut_ptr::<u64>().add(index);
            let curr = core::ptr::read_volatile(entry_ptr);
            if (curr & 1) == 0 {
                None
            } else {
                Some(PhysAddr::new(curr & !0xFFF))
            }
        }
    }

    pub fn clear_entry(table_phys: PhysAddr, index: usize) -> bool {
        if index >= PT_LEVEL_ENTRIES {
            return false;
        }
        let table_virt = crate::memory::phys_to_virt(table_phys);
        if table_virt.is_null() {
            return false;
        }
        unsafe {
            let entry_ptr = table_virt.as_mut_ptr::<u64>().add(index);
            core::ptr::write_volatile(entry_ptr, 0);
        }
        true
    }

    pub fn unmap_slpt_page(root_phys: PhysAddr, iova: PhysAddr) -> bool {
        let iova_u64 = iova.as_u64();
        let pml4_idx = ((iova_u64 >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((iova_u64 >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova_u64 >> 21) & 0x1FF) as usize;
        let pt_idx = ((iova_u64 >> 12) & 0x1FF) as usize;

        let Some(pdpt) = Self::get_next_level(root_phys, pml4_idx) else { return true; };
        let Some(pd) = Self::get_next_level(pdpt, pdpt_idx) else { return true; };
        let Some(pt) = Self::get_next_level(pd, pd_idx) else { return true; };
        Self::clear_entry(pt, pt_idx)
    }

    pub fn clear_context_entry(&self, bus: u8, device: u8, function: u8) -> bool {
        let idx = (device as usize) * 8 + (function as usize);
        if idx >= 256 {
            return false;
        }
        let Some(ctx_phys) = self.bus_context_tables[bus as usize] else {
            return true;
        };
        let ctx_virt = crate::memory::phys_to_virt(ctx_phys);
        if ctx_virt.is_null() {
            return false;
        }
        unsafe {
            let slot = ctx_virt.as_mut_ptr::<u128>().add(idx);
            core::ptr::write_volatile(slot, 0);
        }
        true
    }

    pub fn reclaim_slpt_tables_recursive(table_phys: PhysAddr, level: u8, free_self: bool) -> usize {
        let mut freed = 0usize;
        let table_virt = crate::memory::phys_to_virt(table_phys);
        if !table_virt.is_null() {
            unsafe {
                let entries = table_virt.as_mut_ptr::<u64>();
                if level > 1 {
                    for i in 0..PT_LEVEL_ENTRIES {
                        let entry = core::ptr::read_volatile(entries.add(i));
                        if (entry & 1) != 0 {
                            let child = PhysAddr::new(entry & !0xFFF);
                            freed += Self::reclaim_slpt_tables_recursive(child, level - 1, true);
                            core::ptr::write_volatile(entries.add(i), 0);
                        }
                    }
                } else {
                    for i in 0..PT_LEVEL_ENTRIES {
                        core::ptr::write_volatile(entries.add(i), 0);
                    }
                }
            }
        }

        if free_self {
            let frame = PhysFrame::<Size4KiB>::containing_address(table_phys);
            crate::memory::deallocate_frame(frame);
            freed += 1;
        }
        freed
    }
}