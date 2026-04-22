// src/arch/x86_64/vmx/controls.rs
use crate::arch::x86_64::vmx::{
    instructions::vmwrite,
    vmcs::VmcsField,
    IA32_VMX_BASIC, IA32_VMX_ENTRY_CTLS, IA32_VMX_EXIT_CTLS, IA32_VMX_PINBASED_CTLS,
    IA32_VMX_PROCBASED_CTLS, IA32_VMX_PROCBASED_CTLS2,
};
use x86_64::{registers::model_specific::Msr, PhysAddr};

const VMX_PREEMPTION_TIMER_RATE: u32 = 1_000_000;

pub(super) fn setup_control_fields(ept_pointer: u64, vpid: u16, pml_pointer: PhysAddr) {
    unsafe {
        vmwrite(VmcsField::VmcsLinkPointer as u64, !0u64);

        let exit_ctrls = adjust_vmx_control(
            IA32_VMX_EXIT_CTLS,
            (1 << 9) | (1 << 15) | (1 << 18) | (1 << 20),
        );
        vmwrite(VmcsField::VmExitControls as u64, exit_ctrls);

        let pin_ctrls = adjust_vmx_control(IA32_VMX_PINBASED_CTLS, (1 << 0) | (1 << 6));
        vmwrite(VmcsField::PinBasedVmExecControl as u64, pin_ctrls);
        vmwrite(VmcsField::VmxPreemptionTimerValue as u64, VMX_PREEMPTION_TIMER_RATE as u64);

        let entry_ctrls = adjust_vmx_control(IA32_VMX_ENTRY_CTLS, 0);
        vmwrite(VmcsField::VmEntryControls as u64, entry_ctrls);

        let proc_ctrls = adjust_vmx_control(IA32_VMX_PROCBASED_CTLS, 0x80000000);
        vmwrite(
            VmcsField::PrimaryProcessorBasedVmExecControl as u64,
            proc_ctrls,
        );

        let sec_proc_ctrls = adjust_vmx_control(IA32_VMX_PROCBASED_CTLS2, 0x82 | (1 << 5) | (1 << 17));
        if (sec_proc_ctrls & 0x80) == 0 {
            panic!("运行权限阻断: 中央处理器微指令缺乏针对无约束执行流 (Unrestricted Guest) 的支持");
        }
        vmwrite(
            VmcsField::SecondaryProcessorBasedVmExecControl as u64,
            sec_proc_ctrls,
        );

        vmwrite(VmcsField::VirtualProcessorId as u64, vpid as u64);
        vmwrite(VmcsField::PmlAddress as u64, pml_pointer.as_u64());

        vmwrite(VmcsField::ExceptionBitmap as u64, 0);
        vmwrite(VmcsField::PageFaultErrorCodeMask as u64, 0);
        vmwrite(VmcsField::PageFaultErrorCodeMatch as u64, 0);
        vmwrite(VmcsField::VmExitMsrStoreCount as u64, 0);
        vmwrite(VmcsField::VmExitMsrLoadCount as u64, 0);
        vmwrite(VmcsField::VmEntryMsrLoadCount as u64, 0);
        vmwrite(VmcsField::VmEntryInterruptionInfo as u64, 0);

        vmwrite(VmcsField::EptPointer as u64, ept_pointer);
    }
}

pub fn adjust_vmx_control(msr: u32, requested: u64) -> u64 {
    let basic = unsafe { Msr::new(IA32_VMX_BASIC).read() };
    let true_msr = if (basic & (1 << 55)) != 0 {
        match msr {
            IA32_VMX_PINBASED_CTLS => 0x48D,
            IA32_VMX_PROCBASED_CTLS => 0x48E,
            IA32_VMX_EXIT_CTLS => 0x48F,
            IA32_VMX_ENTRY_CTLS => 0x490,
            _ => msr,
        }
    } else {
        msr
    };

    let val = unsafe { Msr::new(true_msr).read() };
    let allowed_0 = val as u32;
    let allowed_1 = (val >> 32) as u32;
    let mut actual = requested as u32;
    actual &= allowed_1;
    actual |= allowed_0;
    actual as u64
}