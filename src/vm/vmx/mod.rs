// src/vm/vmx/mod.rs

use crate::arch::x86_64::vmx::{
    instructions::{vmclear, vmptrld, vmread},
    vmcs::VmcsField,
};
use x86_64::PhysAddr;

mod controls;
mod guest;
mod host;

pub use host::set_tr;

pub fn prepare_first_guest(vmcs_region_phys: u64, guest_rip: u64, guest_rsp: u64, ept_pointer: u64) {
    clear_and_load_vmcs(vmcs_region_phys);
    host::setup_host_state();
    controls::setup_control_fields(ept_pointer);
    guest::setup_guest_state(guest_rip, guest_rsp);
    dump_vmcs();
}

fn clear_and_load_vmcs(vmcs_region_phys: u64) {
    unsafe {
        vmclear(PhysAddr::new(vmcs_region_phys));
        vmptrld(PhysAddr::new(vmcs_region_phys));
    }
}

pub fn dump_vmcs() {
    unsafe {
        crate::serial_println!("\n--- VMCS DUMP ---");
        crate::serial_println!("  EPT Pointer:            {:#018x}", vmread(VmcsField::EptPointer as u64));
        crate::serial_println!("  RIP: {:#018x}  RSP: {:#018x}", vmread(VmcsField::GuestRip as u64), vmread(VmcsField::GuestRsp as u64));
        crate::serial_println!("--- END VMCS DUMP ---\n");
    }
}