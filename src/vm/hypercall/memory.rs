// src/vm/hypercall/memory.rs
use core::convert::TryInto;
use x86_64::PhysAddr;
use crate::arch::x86_64::vmx::GuestRegisters;
use crate::coherence::fence_and_invalidate_all_epts;
use crate::memory::ept::EptFlags;
use super::types::{HypercallArgs, HypercallHandler, HC_SUCCESS, HC_INVALID_CALL, HC_INVALID_ENCLAVE, HC_PERMISSION_DENIED, HC_NOT_IMPLEMENTED};
use super::utils::copy_guest_gpa_bytes;

pub struct PageTransferHandler;
impl HypercallHandler for PageTransferHandler {
    fn handle(&self, args: HypercallArgs, _regs: &mut GuestRegisters) -> u64 {
        crate::log_debug!("收到路由授权请求：源节点={}, 目标={}, 地址偏移={:#x} 指向 {:#x}", 
            args.arg1, args.arg2, args.arg3, args.arg5);
        
        let mut enclave_mgr_guard = crate::enclave::get_manager();
        let enclave_mgr = match enclave_mgr_guard.as_mut() {
            Some(mgr) => mgr,
            None => return HC_INVALID_CALL,
        };
        
        let src_ept_ptr: *mut crate::memory::ept::EptManager = match enclave_mgr.get_enclave_mut(args.arg1 as u32) {
            Some(e) => &mut e.ept,
            None => return HC_INVALID_ENCLAVE,
        };
        
        let dst_ept_ptr: *mut crate::memory::ept::EptManager = match enclave_mgr.get_enclave_mut(args.arg2 as u32) {
            Some(e) => &mut e.ept,
            None => return HC_INVALID_ENCLAVE,
        };

        let mut msb_guard = crate::msb::get_manager();
        if let Some(msb) = msb_guard.as_mut() {
            let success = msb.transfer_page_ownership(
                args.arg1 as u32,
                args.arg2 as u32,
                unsafe { &mut *src_ept_ptr },
                unsafe { &mut *dst_ept_ptr },
                PhysAddr::new(args.arg3),
                PhysAddr::new(args.arg5),
                crate::memory::ept::EptFlags::from_bits_truncate(args.arg4)
            );
            if success { HC_SUCCESS } else { HC_PERMISSION_DENIED }
        } else {
            HC_NOT_IMPLEMENTED
        }
    }
}

const PAGE_TRANSFER_DESC_BYTES: usize = 24;
const PAGE_TRANSFER_BATCH_MAX: usize = 32;

pub struct PageTransferBatchHandler;
impl HypercallHandler for PageTransferBatchHandler {
    fn handle(&self, args: HypercallArgs, _regs: &mut GuestRegisters) -> u64 {
        let count = args.arg4 as usize;
        if count == 0 || count > PAGE_TRANSFER_BATCH_MAX {
            return HC_INVALID_CALL;
        }
        let need = count.checked_mul(PAGE_TRANSFER_DESC_BYTES).unwrap_or(usize::MAX);
        if need > PAGE_TRANSFER_DESC_BYTES * PAGE_TRANSFER_BATCH_MAX {
            return HC_INVALID_CALL;
        }

        let mut raw =[0u8; PAGE_TRANSFER_DESC_BYTES * PAGE_TRANSFER_BATCH_MAX];
        {
            let mut mgr = crate::enclave::get_manager();
            let manager = match mgr.as_mut() {
                Some(m) => m,
                None => return HC_NOT_IMPLEMENTED,
            };
            let cur = match manager.current_id() {
                Some(id) => id,
                None => return HC_INVALID_ENCLAVE,
            };
            let enclave = match manager.get_enclave_mut(cur) {
                Some(e) => e,
                None => return HC_INVALID_ENCLAVE,
            };
            let nread = copy_guest_gpa_bytes(&enclave.ept, args.arg3, &mut raw[..need]);
            if nread < need {
                return HC_INVALID_CALL;
            }
        }

        let mut pages =[(
            PhysAddr::new(0),
            PhysAddr::new(0),
            EptFlags::empty(),
        ); PAGE_TRANSFER_BATCH_MAX];
        for i in 0..count {
            let o = i * PAGE_TRANSFER_DESC_BYTES;
            let src = u64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
            let dst = u64::from_le_bytes(raw[o + 8..o + 16].try_into().unwrap());
            let fl = u64::from_le_bytes(raw[o + 16..o + 24].try_into().unwrap());
            pages[i] = (
                PhysAddr::new(src),
                PhysAddr::new(dst),
                EptFlags::from_bits_truncate(fl),
            );
        }

        let mut enclave_mgr_guard = crate::enclave::get_manager();
        let enclave_mgr = match enclave_mgr_guard.as_mut() {
            Some(m) => m,
            None => return HC_INVALID_CALL,
        };
        let src_ept_ptr: *mut crate::memory::ept::EptManager =
            match enclave_mgr.get_enclave_mut(args.arg1 as u32) {
                Some(e) => &mut e.ept,
                None => return HC_INVALID_ENCLAVE,
            };
        let dst_ept_ptr: *mut crate::memory::ept::EptManager =
            match enclave_mgr.get_enclave_mut(args.arg2 as u32) {
                Some(e) => &mut e.ept,
                None => return HC_INVALID_ENCLAVE,
            };

        let mut msb_guard = crate::msb::get_manager();
        if let Some(msb) = msb_guard.as_mut() {
            let transferred = msb.transfer_pages(
                args.arg1 as u32,
                args.arg2 as u32,
                unsafe { &mut *src_ept_ptr },
                unsafe { &mut *dst_ept_ptr },
                &pages[..count],
            );
            return transferred as u64;
        }
        HC_NOT_IMPLEMENTED
    }
}

pub struct MapSharedReadOnlyHandler;
impl HypercallHandler for MapSharedReadOnlyHandler {
    fn handle(&self, args: HypercallArgs, _regs: &mut GuestRegisters) -> u64 {
        let mut mgr = crate::enclave::get_manager();
        let manager = match mgr.as_mut() {
            Some(m) => m,
            None => return HC_NOT_IMPLEMENTED,
        };

        let src_id = args.arg1 as u32;
        let dst_id = args.arg2 as u32;
        let gpa = PhysAddr::new(args.arg3);

        let src_ept = match manager.get_enclave(src_id) {
            Some(e) => &e.ept as *const _,
            None => return HC_INVALID_ENCLAVE,
        };
        let dst_ept = match manager.get_enclave_mut(dst_id) {
            Some(e) => &mut e.ept as *mut _,
            None => return HC_INVALID_ENCLAVE,
        };

        let mut msb = crate::msb::get_manager();
        let success = unsafe {
            msb.as_mut().unwrap().map_shared_readonly(src_id, dst_id, &*src_ept, &mut *dst_ept, gpa)
        };
        
        if success { HC_SUCCESS } else { HC_PERMISSION_DENIED }
    }
}

pub struct PageTransferAsyncHandler;
impl HypercallHandler for PageTransferAsyncHandler {
    fn handle(&self, args: HypercallArgs, _regs: &mut GuestRegisters) -> u64 {
        let mut mgr = crate::enclave::get_manager();
        let manager = match mgr.as_mut() {
            Some(m) => m,
            None => return HC_NOT_IMPLEMENTED,
        };
        let src_id = args.arg1 as u32;
        let dst_id = args.arg2 as u32;
        let src_gpa = PhysAddr::new(args.arg3);
        let dst_gpa = PhysAddr::new(args.arg5);
        let flags = EptFlags::from_bits_truncate(args.arg4);

        let src_ept = match manager.get_enclave_mut(src_id) {
            Some(e) => &mut e.ept as *mut _,
            None => return HC_INVALID_ENCLAVE,
        };
        let dst_ept = match manager.get_enclave_mut(dst_id) {
            Some(e) => &mut e.ept as *mut _,
            None => return HC_INVALID_ENCLAVE,
        };

        let mut msb = crate::msb::get_manager();
        let success = unsafe {
            msb.as_mut().unwrap().transfer_page_ownership_async(src_id, dst_id, &mut *src_ept, &mut *dst_ept, src_gpa, dst_gpa, flags)
        };

        if success { HC_SUCCESS } else { HC_PERMISSION_DENIED }
    }
}

pub struct FenceStressHandler;
impl HypercallHandler for FenceStressHandler {
    fn handle(&self, args: HypercallArgs, _regs: &mut GuestRegisters) -> u64 {
        use x86_64::registers::model_specific::Msr;
        let n = (args.arg1 as u64).clamp(1, 1_000_000);
        let t0 = unsafe { Msr::new(0x10).read() };
        for _ in 0..n {
            fence_and_invalidate_all_epts();
        }
        let t1 = unsafe { Msr::new(0x10).read() };
        crate::log_debug!("内存屏障及管线冲刷指令压测完毕: 重复次数 {}  时钟周期损耗={}", n, t1.wrapping_sub(t0));
        HC_SUCCESS
    }
}