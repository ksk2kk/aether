/* src/arch/x86_64/virtualization.rs */
use x86_64::PhysAddr;

pub trait VirtualizationProvider: Send + Sync {
    fn check_support(&self);
    fn enable(&mut self);
    fn enter_root_mode(&mut self);
    fn launch_guest(&self);
    fn get_revision_id(&self) -> u32;

    fn prepare_guest(
        &self,
        vmcs_region: PhysAddr,
        guest_rip: u64,
        guest_rsp: u64,
        ept_pointer: u64,
        vpid: u16,
        pml_pointer: PhysAddr,
    );
}