// src/memory/buddy.rs

use x86_64::{
    structures::paging::{FrameAllocator, PhysFrame, Size4KiB},
    PhysAddr,
};

const MAX_ORDER: usize = 20;
const LIST_END: u32 = u32::MAX;
const FREE_MAGIC: u32 = 0x90EE_A10C;

pub struct BuddyFrameAllocator {
    bitmap: &'static mut [u64],
    total_frames: usize,
    free_head: [u32; MAX_ORDER + 1],
}

impl BuddyFrameAllocator {
    pub fn new(bitmap: &'static mut [u64], total_frames: usize) -> Self {
        let mut s = Self {
            bitmap,
            total_frames,
            free_head: [LIST_END; MAX_ORDER + 1],
        };
        s.rebuild_free_lists();
        s
    }

    pub fn mark_allocated(&mut self, pfn: usize) {
        let idx = pfn / 64;
        let bit = pfn % 64;
        if idx < self.bitmap.len() {
            self.bitmap[idx] |= 1 << bit;
        }
    }

    fn rebuild_free_lists(&mut self) {
        for h in &mut self.free_head {
            *h = LIST_END;
        }
        let tf = self.total_frames;
        let mut pfn = 0usize;
        while pfn < tf {
            if self.is_allocated(pfn) {
                pfn += 1;
                continue;
            }
            let start = pfn;
            while pfn < tf && !self.is_allocated(pfn) {
                pfn += 1;
            }
            let len = pfn - start;
            self.add_interval(start, len);
        }
    }

    fn add_interval(&mut self, mut start: usize, mut len: usize) {
        while len > 0 {
            let order = self.max_block_order(start, len, MAX_ORDER);
            let size = 1usize << order;
            self.push_block(order, start as u32);
            start += size;
            len -= size;
        }
    }

    fn max_block_order(&self, start: usize, len: usize, cap: usize) -> usize {
        let mut order = cap.min(start.trailing_zeros() as usize).min(len.ilog2() as usize);
        loop {
            let sz = 1usize << order;
            if sz <= len && start % sz == 0 { return order; }
            if order == 0 { return 0; }
            order -= 1;
        }
    }

    #[inline]
    fn is_allocated(&self, pfn: usize) -> bool {
        let idx = pfn / 64;
        let bit = pfn % 64;
        if idx >= self.bitmap.len() { return true; }
        (self.bitmap[idx] & (1 << bit)) != 0
    }

    fn push_block(&mut self, order: usize, pfn: u32) {
        let head = self.free_head[order];
        let va = crate::memory::phys_to_virt(PhysAddr::new(u64::from(pfn) * 4096));
        unsafe {
            let p = va.as_mut_ptr::<u32>();
            p.write_volatile(FREE_MAGIC);
            p.add(1).write_volatile(head);
        }
        self.free_head[order] = pfn;
    }

    fn pop_block(&mut self, order: usize) -> Option<usize> {
        let pfn = self.free_head[order];
        if pfn == LIST_END { return None; }
        let va = crate::memory::phys_to_virt(PhysAddr::new(u64::from(pfn) * 4096));
        unsafe {
            let p = va.as_mut_ptr::<u32>();
            if p.read_volatile() != FREE_MAGIC { return None; }
            self.free_head[order] = p.add(1).read_volatile();
        }
        Some(pfn as usize)
    }

    pub fn deallocate_frame(&mut self, frame: PhysFrame) {
        let pfn = (frame.start_address().as_u64() / 4096) as usize;
        let idx = pfn / 64;
        let bit = pfn % 64;
        self.bitmap[idx] &= !(1 << bit);
        self.push_block(0, pfn as u32);
    }
}

unsafe impl FrameAllocator<Size4KiB> for BuddyFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let mut order = (0..=MAX_ORDER).find(|&k| self.free_head[k] != LIST_END)?;
        let pfn = self.pop_block(order)?;
        while order > 0 {
            order -= 1;
            let buddy = pfn + (1 << order);
            self.push_block(order, buddy as u32);
        }
        self.mark_allocated(pfn);
        Some(PhysFrame::containing_address(PhysAddr::new(pfn as u64 * 4096)))
    }
}