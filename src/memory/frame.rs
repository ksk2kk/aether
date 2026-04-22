// src/memory/frame.rs
use multiboot2::{MemoryAreaType, MemoryMapTag};
use spin::Mutex;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::{structures::paging::{FrameAllocator, PhysFrame}, PhysAddr, VirtAddr};
use super::buddy::BuddyFrameAllocator;

static FRAME_ALLOCATOR: Mutex<Option<BuddyFrameAllocator>> = Mutex::new(None);
pub static PHYSICAL_MEMORY_OFFSET: AtomicU64 = AtomicU64::new(0);

pub fn init(memory_map_tag: &MemoryMapTag) {
    PHYSICAL_MEMORY_OFFSET.store(0, Ordering::SeqCst);

    let total_pages = calculate_total_pages(memory_map_tag);
    let bitmap_size = (total_pages + 7) / 8;
    let bitmap_pages = (bitmap_size + 4095) / 4096;

    let bitmap_addr = find_bitmap_region(memory_map_tag, bitmap_size);
    initialize_allocator_bitmap(bitmap_addr, bitmap_size, bitmap_pages, memory_map_tag, total_pages);
}

pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(phys.as_u64() + PHYSICAL_MEMORY_OFFSET.load(Ordering::SeqCst))
}

fn calculate_total_pages(memory_map_tag: &MemoryMapTag) -> usize {
    let mut total_pages: usize = 0;
    for region in memory_map_tag.memory_areas().iter() {
        let last_addr = region.end_address();
        let pages = (last_addr / 4096) as usize;
        if pages > total_pages {
            total_pages = pages;
        }
    }
    total_pages
}

fn find_bitmap_region(memory_map_tag: &MemoryMapTag, bitmap_size: usize) -> u64 {
    for region in memory_map_tag.memory_areas().iter() {
        if region.typ() == MemoryAreaType::Available {
            let mut start = region.start_address();
            let end = region.end_address();

            if start < 0x800_000 && end > 0x800_000 {
                start = 0x800_000;
            }

            if start >= 0x800_000 && start < end && (end - start) as usize >= bitmap_size {
                return start;
            }
        }
    }
    panic!("底层资源枯竭: 无法在物理映射中找到足够连续内存作为分配位图基底");
}

fn initialize_allocator_bitmap(bitmap_addr: u64, bitmap_size: usize, bitmap_pages: usize, memory_map_tag: &MemoryMapTag, total_pages: usize) {
    unsafe {
        let bitmap_virt_addr = bitmap_addr + PHYSICAL_MEMORY_OFFSET.load(Ordering::SeqCst);
        let bitmap_ptr = bitmap_virt_addr as *mut u64;
        let u64_count = (bitmap_size + 7) / 8;
        
        for i in 0..u64_count {
            bitmap_ptr.add(i).write_volatile(0xFFFF_FFFF_FFFF_FFFF);
        }

        let bitmap_slice = core::slice::from_raw_parts_mut(bitmap_ptr, u64_count);
        
        for region in memory_map_tag.memory_areas().iter() {
            if region.typ() == MemoryAreaType::Available {
                let start = (region.start_address() / 4096) as usize;
                let end = (region.end_address() / 4096) as usize;
                
                let kernel_start_page = 0x100000 / 4096;
                let kernel_end_page = 0x800000 / 4096;
                
                for i in start..end {
                    if i >= kernel_start_page && i < kernel_end_page {
                        continue; 
                    }
                    let idx = i / 64;
                    let bit = i % 64;
                    bitmap_slice[idx] &= !(1 << bit);
                }
            }
        }

        for i in 0..bitmap_pages {
            let page = (bitmap_addr / 4096) as usize + i;
            let idx = page / 64;
            let bit = page % 64;
            bitmap_slice[idx] |= 1 << bit;
        }

        bitmap_slice[0] |= 1;

        *FRAME_ALLOCATOR.lock() = Some(BuddyFrameAllocator::new(
            bitmap_slice,
            total_pages,
        ));
    }
}

pub fn allocate_frame() -> Option<PhysFrame> {
    if let Some(allocator) = FRAME_ALLOCATOR.lock().as_mut() {
        allocator.allocate_frame()
    } else {
        None
    }
}

pub fn deallocate_frame(frame: PhysFrame) {
    if let Some(allocator) = FRAME_ALLOCATOR.lock().as_mut() {
        allocator.deallocate_frame(frame);
    }
}

pub fn mark_allocated(pfn: usize) {
    if let Some(allocator) = FRAME_ALLOCATOR.lock().as_mut() {
        allocator.mark_allocated(pfn);
    }
}