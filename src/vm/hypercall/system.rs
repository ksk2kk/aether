// src/vm/hypercall/system.rs
use crate::arch::x86_64::vmx::GuestRegisters;
use super::types::{HypercallArgs, HypercallHandler, HC_SUCCESS, HC_INVALID_CALL, HC_INVALID_ENCLAVE, HC_NOT_IMPLEMENTED};
use super::utils::copy_guest_gpa_bytes;

pub struct GetHypervisorInfoHandler;
impl HypercallHandler for GetHypervisorInfoHandler {
    fn handle(&self, _args: HypercallArgs, regs: &mut GuestRegisters) -> u64 {
        const MAGIC_U32: u64 = 0x4854_4541;
        const API_LEVEL: u64 = 2;
        regs.rbx = (MAGIC_U32 << 32) | API_LEVEL;
        HC_SUCCESS
    }
}

const DEBUG_MSG_CAP: usize = 512;

pub struct DebugHandler;
impl HypercallHandler for DebugHandler {
    fn handle(&self, args: HypercallArgs, _regs: &mut GuestRegisters) -> u64 {
        let len_req = args.arg2 as usize;
        if len_req == 0 {
            return 0;
        }
        let take = core::cmp::min(len_req, DEBUG_MSG_CAP);
        let mut buf = [0u8; DEBUG_MSG_CAP];

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

        let n = copy_guest_gpa_bytes(&enclave.ept, args.arg1, &mut buf[..take]);
        if n == 0 {
            return HC_INVALID_CALL;
        }

        crate::serial_print!("[隔离域字符流转发]: ");
        for i in 0..n {
            let c = buf[i];
            if c == b'\n' || c == b'\r' || c == b'\t' || (c >= 0x20 && c < 0x7f) {
                crate::serial_print!("{}", c as char);
            } else {
                crate::serial_print!(".");
            }
        }
        crate::serial_println!();
        n as u64
    }
}

#[inline(always)]
fn read_tsc() -> u64 {
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        ((hi as u64) << 32) | lo as u64
    }
}

pub struct MicrobenchHandler;
impl HypercallHandler for MicrobenchHandler {
    fn handle(&self, args: HypercallArgs, _regs: &mut GuestRegisters) -> u64 {
        let iters = core::cmp::min(args.arg1, 1_000_000).max(1) as u32;
        let t0 = read_tsc();
        for _ in 0..iters {
            core::hint::spin_loop();
        }
        let t1 = read_tsc();
        let delta = t1.wrapping_sub(t0);
        crate::log_info!(
            "测速探针：总执行迭代={} 累计时钟位点={} 平均单循环开销={}",
            iters, delta, delta / u64::from(iters)
        );
        HC_SUCCESS
    }
}

pub struct TestHandler;
impl HypercallHandler for TestHandler {
    fn handle(&self, args: HypercallArgs, _regs: &mut GuestRegisters) -> u64 {
        match args.arg1 {
            1 => {
                let g = crate::arch::x86_64::iommu::get_manager();
                if let Some(m) = g.as_ref() {
                    let n = args.arg2.clamp(1, 32) as usize;
                    m.dump_audit_ring_serial(n);
                }
                HC_SUCCESS
            }
            2 => {
                let g = crate::arch::x86_64::iommu::get_manager();
                if let Some(m) = g.as_ref() {
                    m.dump_binding_matrix_serial();
                }
                HC_SUCCESS
            }
            _ => {
                crate::log_debug!(
                    "隔离系统保留开发指令: a1={:#x}, a2={:#x}, a3={:#x}",
                    args.arg1, args.arg2, args.arg3
                );
                HC_SUCCESS
            }
        }
    }
}