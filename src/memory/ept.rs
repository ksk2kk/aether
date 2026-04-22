/* src/memory/ept.rs */
use x86_64::{PhysAddr, structures::paging::PhysFrame};
use bitflags::bitflags;
use super::utils;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct EptFlags: u64 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXECUTE = 1 << 2;
        const MEMORY_TYPE_WB = 6 << 3;
        const IGNORE_PAT = 1 << 6;
        const HUGE_PAGE = 1 << 7;
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EptEntry(u64);

impl EptEntry {
    pub fn new(addr: PhysAddr, flags: EptFlags) -> Self {
        let mut entry = addr.as_u64() & 0x000F_FFFF_FFFF_F000;
        entry |= flags.bits();
        Self(entry)
    }

    pub fn is_unused(&self) -> bool {
        self.0 == 0
    }

    pub fn set_unused(&mut self) {
        self.0 = 0;
    }

    pub fn address(&self) -> PhysAddr {
        PhysAddr::new(self.0 & 0x000F_FFFF_FFFF_F000)
    }

    pub fn is_huge(&self) -> bool {
        (self.0 & EptFlags::HUGE_PAGE.bits()) != 0
    }
}

#[repr(C, align(4096))]
pub struct EptPageTable {
    pub entries: [EptEntry; 512],
}

impl EptPageTable {
    pub const fn new() -> Self {
        Self {
            entries:[EptEntry(0); 512],
        }
    }
}

pub struct EptManager {
    pml4_frame: PhysFrame,
}

impl EptManager {
    pub fn new() -> Self {
        let frame = crate::memory::allocate_frame().expect("EPT 嵌套顶层页表分配被拒: 物理内存池已耗尽");
        let virt = crate::memory::phys_to_virt(frame.start_address());
        unsafe { utils::zero_page(virt); }

        Self {
            pml4_frame: frame,
        }
    }

    pub fn pml4_address(&self) -> PhysAddr {
        self.pml4_frame.start_address()
    }

    pub fn map(&mut self, gpa: PhysAddr, hpa: PhysAddr, flags: EptFlags) {
        let p4_idx = ((gpa.as_u64() >> 39) & 0x1ff) as usize;
        let p3_idx = ((gpa.as_u64() >> 30) & 0x1ff) as usize;
        let p2_idx = ((gpa.as_u64() >> 21) & 0x1ff) as usize;
        let p1_idx = ((gpa.as_u64() >> 12) & 0x1ff) as usize;

        let p3_table = self.get_or_create_table(self.pml4_frame.start_address(), p4_idx);
        let p2_table = self.get_or_create_table(p3_table, p3_idx);
        let p1_table = self.get_or_create_table(p2_table, p2_idx);

        let p1_virt = crate::memory::phys_to_virt(p1_table);
        let p1_ptr = p1_virt.as_u64() as *mut EptEntry;
        unsafe {
            p1_ptr.add(p1_idx).write_volatile(EptEntry::new(hpa, flags));
        }
    }

    pub fn map_2m(&mut self, gpa: PhysAddr, hpa: PhysAddr, flags: EptFlags) {
        let p4_idx = ((gpa.as_u64() >> 39) & 0x1ff) as usize;
        let p3_idx = ((gpa.as_u64() >> 30) & 0x1ff) as usize;
        let p2_idx = ((gpa.as_u64() >> 21) & 0x1ff) as usize;

        let p3_table = self.get_or_create_table(self.pml4_frame.start_address(), p4_idx);
        let p2_table = self.get_or_create_table(p3_table, p3_idx);

        let p2_virt = crate::memory::phys_to_virt(p2_table);
        let p2_ptr = p2_virt.as_u64() as *mut EptEntry;
        unsafe {
            p2_ptr.add(p2_idx).write_volatile(EptEntry::new(hpa, flags | EptFlags::HUGE_PAGE));
        }
    }

    pub fn translate_gpa(&self, gpa: PhysAddr) -> Option<PhysAddr> {
        let p4_idx = ((gpa.as_u64() >> 39) & 0x1ff) as usize;
        let p3_idx = ((gpa.as_u64() >> 30) & 0x1ff) as usize;
        let p2_idx = ((gpa.as_u64() >> 21) & 0x1ff) as usize;
        let p1_idx = ((gpa.as_u64() >> 12) & 0x1ff) as usize;

        let p3_table = self.get_table_only(self.pml4_frame.start_address(), p4_idx)?;
        let p2_table = self.get_table_only(p3_table, p3_idx)?;
        
        let p2_virt = crate::memory::phys_to_virt(p2_table);
        let p2_ptr = p2_virt.as_u64() as *mut EptEntry;
        let p2_entry = unsafe { p2_ptr.add(p2_idx).read_volatile() };
        
        if p2_entry.is_unused() {
            return None;
        }
        
        if p2_entry.is_huge() {
            let offset = gpa.as_u64() & 0x1F_FFFF;
            return Some(PhysAddr::new(p2_entry.address().as_u64() + offset));
        }

        let p1_table = p2_entry.address();
        let p1_virt = crate::memory::phys_to_virt(p1_table);
        let p1_ptr = p1_virt.as_u64() as *mut EptEntry;
        let entry = unsafe { p1_ptr.add(p1_idx).read_volatile() };
        
        if entry.is_unused() {
            None
        } else {
            Some(entry.address())
        }
    }

    pub fn unmap(&mut self, gpa: PhysAddr) -> Option<PhysAddr> {
        let p4_idx = ((gpa.as_u64() >> 39) & 0x1ff) as usize;
        let p3_idx = ((gpa.as_u64() >> 30) & 0x1ff) as usize;
        let p2_idx = ((gpa.as_u64() >> 21) & 0x1ff) as usize;
        let p1_idx = ((gpa.as_u64() >> 12) & 0x1ff) as usize;

        let p3_table = self.get_table_only(self.pml4_frame.start_address(), p4_idx)?;
        let p2_table = self.get_table_only(p3_table, p3_idx)?;
        
        let p2_virt = crate::memory::phys_to_virt(p2_table);
        let p2_ptr = p2_virt.as_u64() as *mut EptEntry;
        let p2_entry = unsafe { p2_ptr.add(p2_idx).read_volatile() };
        
        if p2_entry.is_unused() {
            return None;
        }

        if p2_entry.is_huge() {
            let mut new_entry = p2_entry;
            new_entry.set_unused();
            unsafe {
                p2_ptr.add(p2_idx).write_volatile(new_entry);
            }
            return Some(p2_entry.address());
        }

        let p1_table = p2_entry.address();
        let p1_virt = crate::memory::phys_to_virt(p1_table);
        let p1_ptr = p1_virt.as_u64() as *mut EptEntry;
        
        let old_entry = unsafe { p1_ptr.add(p1_idx).read_volatile() };
        if old_entry.is_unused() {
            return None;
        }

        let mut new_entry = old_entry;
        new_entry.set_unused();
        unsafe {
            p1_ptr.add(p1_idx).write_volatile(new_entry);
        }

        Some(old_entry.address())
    }

    fn get_table_only(&self, parent_table_addr: PhysAddr, index: usize) -> Option<PhysAddr> {
        let parent_virt = crate::memory::phys_to_virt(parent_table_addr);
        let parent_ptr = parent_virt.as_u64() as *mut EptEntry;
        let entry = unsafe { parent_ptr.add(index).read_volatile() };

        if entry.is_unused() {
            None
        } else {
            Some(entry.address())
        }
    }

    fn get_or_create_table(&mut self, parent_table_addr: PhysAddr, index: usize) -> PhysAddr {
        let parent_virt = crate::memory::phys_to_virt(parent_table_addr);
        let parent_ptr = parent_virt.as_u64() as *mut EptEntry;
        let entry = unsafe { parent_ptr.add(index).read_volatile() };

        if entry.is_unused() {
            let new_frame = crate::memory::allocate_frame().expect("EPT 分页树下设表单挂载受阻: 无可用物理帧槽位");
            let new_virt = crate::memory::phys_to_virt(new_frame.start_address());
            unsafe { utils::zero_page(new_virt); }

            let new_entry = EptEntry::new(new_frame.start_address(), EptFlags::READ | EptFlags::WRITE | EptFlags::EXECUTE);
            unsafe {
                parent_ptr.add(index).write_volatile(new_entry);
            }
            new_frame.start_address()
        } else {
            entry.address()
        }
    }

    pub fn identity_map_range(&mut self, start: PhysAddr, size: u64, flags: EptFlags) {
        let mut curr = start.as_u64() & !0xFFF;
        let end = (start.as_u64() + size + 0xFFF) & !0xFFF;
        while curr < end {
            self.map(PhysAddr::new(curr), PhysAddr::new(curr), flags);
            curr += 4096;
        }
    }
}