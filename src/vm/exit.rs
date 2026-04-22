/* src/vm/exit.rs */
use crate::arch::x86_64::vmx::{GuestRegisters, instructions::vmread, vmcs::VmcsField};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    ExceptionOrNmi,
    ExternalInterrupt,
    TripleFault,
    Init,
    Sipi,
    IoSmi,
    OtherSmi,
    InterruptWindow,
    NmiWindow,
    TaskSwitch,
    Cpuid,
    Hlt,
    Invd,
    Invlpg,
    Rdpmc,
    Rdtsc,
    Rsm,
    Vmcall,
    Vmclear,
    Vmlaunch,
    Vmptrld,
    Vmptrst,
    Vmread,
    Vmresume,
    Vmwrite,
    Vmxoff,
    Vmxon,
    CrAccess,
    DrAccess,
    Io,
    Msr,
    FailedVmEntry,
    FailedVmExit,
    EptViolation,
    EptMisconfig,
    Invept,
    Invvpid,
    VmxPreemptionTimer,
    Wbinvd,
    Xsetbv,
    ApicWrite,
    Rdrand,
    Invpcid,
    Vmfunc,
    Encls,
    Unhandled(u32),
}

impl ExitReason {
    pub fn from_u32(val: u32) -> Self {
        match val {
            0 => ExitReason::ExceptionOrNmi,
            1 => ExitReason::ExternalInterrupt,
            2 => ExitReason::TripleFault,
            3 => ExitReason::Init,
            4 => ExitReason::Sipi,
            5 => ExitReason::IoSmi,
            6 => ExitReason::OtherSmi,
            7 => ExitReason::InterruptWindow,
            8 => ExitReason::NmiWindow,
            9 => ExitReason::TaskSwitch,
            10 => ExitReason::Cpuid,
            12 => ExitReason::Hlt,
            13 => ExitReason::Invd,
            14 => ExitReason::Invlpg,
            15 => ExitReason::Rdpmc,
            16 => ExitReason::Rdtsc,
            17 => ExitReason::Rsm,
            18 => ExitReason::Vmcall,
            19 => ExitReason::Vmclear,
            20 => ExitReason::Vmlaunch,
            21 => ExitReason::Vmptrld,
            22 => ExitReason::Vmptrst,
            23 => ExitReason::Vmread,
            24 => ExitReason::Vmresume,
            25 => ExitReason::Vmwrite,
            26 => ExitReason::Vmxoff,
            27 => ExitReason::Vmxon,
            28 => ExitReason::CrAccess,
            29 => ExitReason::DrAccess,
            30 => ExitReason::Io,
            31 => ExitReason::Msr,
            32 => ExitReason::FailedVmEntry,
            33 => ExitReason::FailedVmExit,
            48 => ExitReason::EptViolation,
            49 => ExitReason::EptMisconfig,
            50 => ExitReason::Invept,
            51 => ExitReason::Invvpid,
            52 => ExitReason::VmxPreemptionTimer,
            53 => ExitReason::Wbinvd,
            54 => ExitReason::Xsetbv,
            55 => ExitReason::ApicWrite,
            56 => ExitReason::Rdrand,
            57 => ExitReason::Invpcid,
            58 => ExitReason::Vmfunc,
            59 => ExitReason::Encls,
            x => ExitReason::Unhandled(x),
        }
    }
}

fn handle_vmcall(regs: &mut GuestRegisters) -> bool {
    let hypercall_nr = regs.rcx as u8;
    let args = crate::vm::hypercall::HypercallArgs {
        arg1: regs.rdx,
        arg2: regs.rsi,
        arg3: regs.rdi,
        arg4: regs.r8,
        arg5: regs.r9,
    };

    regs.rax = crate::vm::hypercall::dispatch(args, regs, hypercall_nr);
    true
}

fn handle_msr_access(regs: &mut GuestRegisters, exit_qual: u64) -> bool {
    let msr_id = regs.rcx as u32;
    let is_write = exit_qual != 0;

    if is_write {
        crate::log_debug!("拦截到隔离域 MSR 写入: {:#x} 内容: {:#x}:{:#x}", msr_id, regs.rdx, regs.rax);
    } else {
        match msr_id {
            0x1b => {
                regs.rax = 0xfee00000 | (1 << 11);
                regs.rdx = 0;
            }
            0xc0000100 => {
                regs.rax = 0;
                regs.rdx = 0;
            }
            _ => {
                regs.rax = 0;
                regs.rdx = 0;
            }
        }
    }
    true
}

fn handle_preemption_timer(regs: &mut GuestRegisters) -> bool {
    let mut enclave_mgr_guard = crate::enclave::get_manager();
    if let Some(manager) = enclave_mgr_guard.as_mut() {
        manager.schedule_next(regs);
    }
    true
}

pub fn dispatch_exit(reason: ExitReason, regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    match reason {
        ExitReason::Hlt => false,
        ExitReason::Vmcall => handle_vmcall(regs),
        ExitReason::Msr => handle_msr_access(regs, exit_qual),
        ExitReason::VmxPreemptionTimer => handle_preemption_timer(regs),
        ExitReason::Cpuid => {
            let leaf = regs.rax as u32;
            match leaf {
                0x1 => {
                    regs.rax = 0x000306A9;
                    regs.rbx = 0;
                    regs.rcx = 1 << 31;
                    regs.rdx = 0;
                }
                _ => {
                    regs.rax = 0;
                    regs.rbx = 0;
                    regs.rcx = 0;
                    regs.rdx = 0;
                }
            }
            true
        }
        ExitReason::Rdtsc => {
            regs.rax = 0;
            regs.rdx = 0;
            true
        }
        ExitReason::Rdpmc => {
            regs.rax = 0;
            regs.rdx = 0;
            true
        }
        ExitReason::Invd | ExitReason::Wbinvd => true,
        ExitReason::Xsetbv => true,
        ExitReason::ExceptionOrNmi => {
            let inter_info = unsafe { vmread(VmcsField::ExitInterruptionInfo as u64) };
            crate::log_warn!("捕获不可屏蔽异常向量: {}, 现场限定: {:#x} - 执行流挂起中", inter_info & 0xFF, exit_qual);
            false
        }
        ExitReason::ExternalInterrupt => {
            let exit_intr = unsafe { vmread(VmcsField::ExitInterruptionInfo as u64) };
            let guard = crate::arch::x86_64::apic::get_manager();
            if let Some(apic) = guard.as_ref() {
                apic.route_external_interrupt_vmexit(exit_intr);
            }
            true
        }
        ExitReason::EptViolation => {
            let gpa = unsafe { vmread(VmcsField::GuestPhysicalAddress as u64) };
            let is_write = (exit_qual & 0b10) != 0;
            
            if is_write {
                let mut handled = false;
                let mut mgr_guard = crate::enclave::get_manager();
                if let Some(m) = mgr_guard.as_mut() {
                    if let Some(id) = m.current_id() {
                        if let Some(enclave) = m.get_enclave_mut(id) {
                            let mut ledger = crate::mmdl::ledger();
                            handled = ledger.handle_cow_fault(x86_64::PhysAddr::new(gpa), &mut enclave.ept, id as u16);
                        }
                    }
                }
                if handled {
                    return true;
                }
            }
            crate::log_warn!("隔离边界遭破坏：非法 EPT 访问 RIP={:#x} GPA={:#x} 限定位={:#x}", guest_rip, gpa, exit_qual);
            false
        }
        ExitReason::EptMisconfig => {
            crate::log_error!("物理环境降级：EPT 页表构造受损 RIP={:#x} 限定位={:#x}", guest_rip, exit_qual);
            false
        }
        _ => {
            crate::log_error!("无可恢复路径错误 {:?} 现场RIP={:#x} 限定位={:#x} (目标隔离域已进入销毁队列)", reason, guest_rip, exit_qual);
            false
        }
    }
}