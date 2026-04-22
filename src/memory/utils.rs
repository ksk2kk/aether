use x86_64::VirtAddr;

pub unsafe fn zero_page(virt: VirtAddr) {
    let ptr = virt.as_u64() as *mut u64;
    for i in 0..512 {
        ptr.add(i).write_volatile(0);
    }
}

pub unsafe fn zero_bytes(virt: VirtAddr, size: usize) {
    let ptr = virt.as_mut_ptr::<u8>();
    core::ptr::write_bytes(ptr, 0, size);
}
