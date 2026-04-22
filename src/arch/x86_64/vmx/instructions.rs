// src/arch/x86_64/vmx/instructions.rs
use super::vmcs::VmcsField;
use core::arch::asm;
use x86_64::PhysAddr;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct InveptDescriptor {
    pub ept_pointer: u64,
    pub reserved: u64,
}

#[inline]
pub unsafe fn vmwrite(field: u64, value: u64) {
    let failed: u8;
    asm!(
        "vmwrite %rcx, %rdx",
        "setc %r8b",
        in("rcx") value,
        in("rdx") field,
        out("r8b") failed,
        options(att_syntax, nostack),
    );
    if failed != 0 {
        let err_code = vmread(VmcsField::VmInstructionError as u64);
        crate::log_error!("硬件级覆写操作中止: VMWRITE 失败，指向位域 {:#x}。底层错误码: {:#x}", field, err_code);
        panic!("指令流水线无法继续: VMWRITE");
    }
}

#[inline]
pub unsafe fn vmread(field: u64) -> u64 {
    let value: u64;
    let failed: u8;
    asm!(
        "vmread %rdx, %rax",
        "setc %r8b",
        in("rdx") field,
        out("rax") value,
        out("r8b") failed,
        options(att_syntax, nostack),
    );
    if failed != 0 {
        panic!("执行数据总线拦截异常: VMREAD 失败。位域: {:#x}", field);
    }
    value
}

#[inline]
pub unsafe fn invept(type_: u64, descriptor: &InveptDescriptor) {
    let mut flags: u64;
    asm!(
        "invept {0},[{1}]",
        "pushfq",
        "pop {2}",
        in(reg) type_,
        in(reg) descriptor,
        out(reg) flags,
        options(nostack)
    );
    if (flags & (1 << 0)) != 0 || (flags & (1 << 6)) != 0 {
        panic!("扩展分页表失效执行被硬件回退: 标志位组 {:#x}", flags);
    }
}

pub fn invept_all() {
    unsafe {
        let desc = InveptDescriptor {
            ept_pointer: 0,
            reserved: 0,
        };
        invept(2, &desc);
    }
}

#[inline]
pub unsafe fn invept_single_context(eptp: u64) {
    let desc = InveptDescriptor {
        ept_pointer: eptp,
        reserved: 0,
    };
    invept(1, &desc);
}

#[inline]
pub unsafe fn invvpid_single_context(vpid: u16) {
    #[repr(C)]
    struct InvvpidDescriptor {
        vpid: u64,
        linear_address: u64,
    }
    let desc = InvvpidDescriptor {
        vpid: vpid as u64,
        linear_address: 0,
    };
    let mut flags: u64;
    asm!(
        "invvpid {0}, [{1}]",
        "pushfq",
        "pop {2}",
        in(reg) 1u64,
        in(reg) &desc,
        out(reg) flags,
        options(nostack)
    );
    if (flags & 0x41) != 0 {
        panic!("虚拟进程失效执行异常: VPID={}, 返回标志组={:#x}", vpid, flags);
    }
}

pub unsafe fn vmclear(addr: PhysAddr) {
    let mut flags: u64;
    let phys_addr = addr.as_u64();
    asm!(
        "vmclear[{0}]",
        "pushfq",
        "pop {1}",
        in(reg) &phys_addr,
        out(reg) flags,
        options(nostack)
    );
    if (flags & 0x41) != 0 {
        panic!("清除 VMCS 数据异常，目标页 {:#x} 标志组 {:#x}", phys_addr, flags);
    }
}

pub unsafe fn vmptrld(addr: PhysAddr) {
    let mut flags: u64;
    let phys_addr = addr.as_u64();
    asm!(
        "vmptrld [{0}]",
        "pushfq",
        "pop {1}",
        in(reg) &phys_addr,
        out(reg) flags,
        options(nostack)
    );
    if (flags & 0x41) != 0 {
        panic!("装载 VMCS 执行异常，目标页 {:#x} 标志组 {:#x}", phys_addr, flags);
    }
}