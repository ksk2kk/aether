// src/vm/hypercall/utils.rs
use x86_64::PhysAddr;

pub fn copy_guest_gpa_bytes(ept: &crate::memory::ept::EptManager, gpa: u64, buf: &mut [u8]) -> usize {
    let mut filled = 0usize;
    let mut curr = gpa;
    while filled < buf.len() {
        let page = curr & !0xFFF;
        let off = (curr & 0xFFF) as usize;
        let Some(hpa) = ept.translate_gpa(PhysAddr::new(page)) else {
            break;
        };
        let virt = crate::memory::phys_to_virt(hpa);
        if virt.is_null() {
            break;
        };
        let step = core::cmp::min(buf.len() - filled, 4096 - off);
        unsafe {
            let src = virt.as_u64() as *const u8;
            core::ptr::copy_nonoverlapping(src.add(off), buf.as_mut_ptr().add(filled), step);
        }
        filled += step;
        curr += step as u64;
    }
    filled
}

pub fn copy_bytes_to_guest_gpa(ept: &crate::memory::ept::EptManager, gpa: u64, buf: &[u8]) -> usize {
    let mut written = 0usize;
    let mut curr_gpa = gpa;
    while written < buf.len() {
        let page_gpa = curr_gpa & !0xFFF;
        let offset_in_page = (curr_gpa & 0xFFF) as usize;
        let Some(hpa) = ept.translate_gpa(PhysAddr::new(page_gpa)) else {
            break;
        };
        let virt = crate::memory::phys_to_virt(hpa);
        if virt.is_null() {
            break;
        };

        let bytes_to_write = core::cmp::min(buf.len() - written, 4096 - offset_in_page);
        unsafe {
            let dst_ptr = virt.as_mut_ptr::<u8>().add(offset_in_page);
            let src_ptr = buf.as_ptr().add(written);
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, bytes_to_write);
        }
        written += bytes_to_write;
        curr_gpa += bytes_to_write as u64;
    }
    written
}