// src/memory/heap.rs
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use spin::Mutex;
pub use linked_list_allocator::Heap;
use multiboot2::{MemoryAreaType, MemoryMapTag};
use x86_64::PhysAddr;

pub struct HeapAllocator {
    heap: Mutex<Heap>,
}

impl HeapAllocator {
    pub const fn empty() -> Self {
        HeapAllocator {
            heap: Mutex::new(Heap::empty()),
        }
    }

    pub unsafe fn init(&self, start: *mut u8, size: usize) {
        self.heap.lock().init(start, size);
    }
}

unsafe impl GlobalAlloc for HeapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.heap.lock().allocate_first_fit(layout)
            .map_or(ptr::null_mut(), |ptr| ptr.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.heap.lock().deallocate(ptr::NonNull::new_unchecked(ptr), layout);
    }
}

pub fn init(memory_map_tag: &MemoryMapTag) {
    let (heap_start, heap_size) = find_heap_region(memory_map_tag, 64 * 1024 * 1024);
    let heap_virt = crate::memory::phys_to_virt(PhysAddr::new(heap_start));
    
    for i in 0..(heap_size / 4096) {
        let pfn = (heap_start / 4096) as usize + i;
        crate::memory::frame::mark_allocated(pfn);
    }

    unsafe {
        core::ptr::write_bytes(heap_virt.as_mut_ptr::<u8>(), 0, heap_size);
        crate::HEAP_ALLOCATOR.init(heap_virt.as_mut_ptr(), heap_size);
    }
}

fn find_heap_region(memory_map_tag: &MemoryMapTag, min_size: usize) -> (u64, usize) {
    for region in memory_map_tag.memory_areas().iter() {
        if region.typ() == MemoryAreaType::Available {
            let start = region.start_address();
            let end = region.end_address();
            
            let safe_start = if start < 0x2000000 { 0x2000000 } else { start };
            
            if end > safe_start && (end - safe_start) as usize >= min_size {
                return (safe_start, min_size);
            }
        }
    }
    panic!("系统硬件约束错误: 物理空间内未发现足以容纳内核态堆布局的连续区域");
}