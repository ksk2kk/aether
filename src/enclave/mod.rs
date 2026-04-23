/* src/enclave/mod.rs */
pub mod state;
pub mod manager;

pub use state::{Enclave, EnclaveState};
pub use manager::EnclaveManager;

use crate::memory::ept::{EptFlags, EptManager};
use crate::memory::{GuestImageSpec, RealmKind};
use x86_64::PhysAddr;
use crate::arch::x86_64::virtualization::VirtualizationProvider;
use spin::Mutex;
use crate::percpu;
use alloc::vec::Vec;

static ENCLAVE_MANAGER: Mutex<Option<EnclaveManager>> = Mutex::new(None);

pub fn init(virt_provider: &mut dyn VirtualizationProvider) {
    crate::log_debug!("初始化隔离域管理器...");
    
    *ENCLAVE_MANAGER.lock() = Some(EnclaveManager::new());

    crate::vm::fs::init_vfs();
    crate::log_debug!("虚拟文件系统 (VFS) 已初始化");

    crate::vm::syscall::linux::init_process_manager();
    crate::log_debug!("进程管理器已初始化");

    let specs = crate::memory::guest_image_specs();
    let mut registered_ids_vec: Vec<u32> = Vec::new();

    {
        let mut manager_guard = ENCLAVE_MANAGER.lock();
        let manager = manager_guard.as_mut().unwrap();

        for slot in specs.iter().copied() {
            let Some(spec) = slot else { break };
            let vmcs_phys = allocate_and_init_vmcs(virt_provider);
            let pml_phys = allocate_and_init_pml();
            let ept_manager = setup_initial_ept();
            if let Some(id) = manager.register_enclave(ept_manager, vmcs_phys, pml_phys, spec) {
                registered_ids_vec.push(id);
            }
        }

        if registered_ids_vec.is_empty() {
            let vmcs_phys = allocate_and_init_vmcs(virt_provider);
            let pml_phys = allocate_and_init_pml();
            let ept_manager = setup_initial_ept();
            let placeholder = GuestImageSpec {
                module_start: 0,
                module_size: 0,
                load_gpa: 0x8000,
                realm_kind: RealmKind::Micro,
            };
            if let Some(id) = manager.register_enclave(ept_manager, vmcs_phys, pml_phys, placeholder) {
                registered_ids_vec.push(id);
            }
        }
    }

    if registered_ids_vec.is_empty() {
        panic!("系统异常: 未能注册任何隔离域");
    }

    for &id in &registered_ids_vec {
        load_guest_code(id);
    }

    let first_id = *registered_ids_vec.first().expect("first enclave");
    crate::log_info!("已加载 {} 个隔离域，准备启动初始域 {}", registered_ids_vec.len(), first_id);
    launch_first_enclave(first_id, virt_provider);
}

pub fn get_manager() -> spin::MutexGuard<'static, Option<EnclaveManager>> {
    ENCLAVE_MANAGER.lock()
}

pub fn terminate_current_and_yield(regs: &mut crate::arch::x86_64::vmx::GuestRegisters) {
    let mut mgr_guard = get_manager();
    let mgr = mgr_guard.as_mut().unwrap();
    
    if let Some(id) = percpu::get_current_enclave_id() {
        if let Some(e) = mgr.get_enclave_mut(id) {
            e.state = EnclaveState::Terminated;
            unsafe { crate::arch::x86_64::vmx::instructions::vmclear(e.vmcs_phys_addr) };
            crate::log_info!("隔离域 {} 运行终止", id);
        }
    }
    percpu::set_current_enclave_id(None);
    
    if let Some(next_id) = mgr.find_next_ready_enclave(0) {
        percpu::set_current_enclave_id(Some(next_id));
        let next = mgr.get_enclave_mut(next_id).unwrap();
        next.state = EnclaveState::Running;
        *regs = next.regs;
        percpu::set_active_vmcs(next.vmcs_phys_addr.as_u64());
        unsafe { crate::arch::x86_64::vmx::instructions::vmptrld(next.vmcs_phys_addr) };
        crate::log_debug!("已调度并切换至域 {}", next_id);
    } else {
        crate::log_warn!("无可调度的活动隔离域，系统即将挂起。");
        loop { unsafe { core::arch::asm!("hlt") } }
    }
}

fn allocate_and_init_vmcs(virt_provider: &mut dyn VirtualizationProvider) -> PhysAddr {
    let vmcs_frame = crate::memory::allocate_frame().expect("VMCS 帧分配失败");
    let vmcs_phys = vmcs_frame.start_address();
    
    unsafe {
        let vmcs_virt = crate::memory::phys_to_virt(vmcs_phys);
        if !vmcs_virt.is_null() {
            core::ptr::write_bytes(vmcs_virt.as_mut_ptr::<u8>(), 0, 4096);
            let revision_id = virt_provider.get_revision_id();
            let ptr = vmcs_virt.as_mut_ptr::<u32>();
            ptr.write_volatile(revision_id);
        }
    }
    
    vmcs_phys
}

fn allocate_and_init_pml() -> PhysAddr {
    let pml_frame = crate::memory::allocate_frame().expect("PML 缓冲分配失败");
    let pml_phys = pml_frame.start_address();
    let pml_virt = crate::memory::phys_to_virt(pml_phys);
    if !pml_virt.is_null() {
        unsafe {
            core::ptr::write_bytes(pml_virt.as_mut_ptr::<u8>(), 0, 4096);
        }
    }
    pml_phys
}

fn setup_initial_ept() -> EptManager {
    let mut ept_manager = EptManager::new();
    ept_manager.identity_map_range(
        PhysAddr::new(0), 
        0x100000, 
        crate::memory::ept::EptFlags::READ | crate::memory::ept::EptFlags::WRITE | crate::memory::ept::EptFlags::EXECUTE
    );
    ept_manager
}

fn load_guest_code(enclave_id: u32) {
    let mut manager_guard = get_manager();
    let manager = manager_guard.as_mut().unwrap();
    let enclave = manager.get_enclave_mut(enclave_id).expect("装载失败：找不到目标域");

    if enclave.module_size > 0 {
        let module_ptr = crate::memory::phys_to_virt(PhysAddr::new(enclave.module_phys));
        
        if enclave.module_size >= core::mem::size_of::<crate::vm::elf::Elf64Ehdr>() {
            let elf_data = unsafe {
                core::slice::from_raw_parts(module_ptr.as_ptr::<u8>(), enclave.module_size)
            };
            
            if let Ok(ehdr) = crate::vm::elf::ElfLoader::validate_elf(elf_data) {
                crate::log_info!("检测到 ELF 可执行文件，入口点: {:#x}", ehdr.entry_point());
                
                let elf_loader = crate::vm::elf::ElfLoader::new();
                let load_offset = if enclave.realm_kind == crate::memory::RealmKind::Macro {
                    0
                } else {
                    enclave.guest_entry_gpa
                };
                
                match elf_loader.load_elf(elf_data, &mut enclave.ept, load_offset) {
                    Ok(info) => {
                        crate::log_info!("ELF 加载成功: 入口={:#x}, 范围={:#x}-{:#x}", 
                            info.entry_point, info.lowest_vaddr, info.highest_vaddr);
                        enclave.entry_rip = info.entry_point;
                        let stack_pages = 4;
                        let stack_base = info.highest_vaddr + 0x1000;
                        enclave.entry_rsp = stack_base + stack_pages * 4096;
                        return;
                    }
                    Err(e) => {
                        crate::log_error!("ELF 加载失败: {}", e);
                    }
                }
            }
        }
    }

    let base_gpa = enclave.guest_entry_gpa;
    let page_rwx = EptFlags::READ | EptFlags::WRITE | EptFlags::EXECUTE;

    let pages = if enclave.module_size == 0 {
        1usize
    } else {
        (enclave.module_size + 4095) / 4096
    };

    for i in 0..pages {
        let frame = crate::memory::allocate_frame().unwrap_or_else(|| panic!("为镜像分配内存不足"));
        let hpa = frame.start_address();
        let dst = crate::memory::phys_to_virt(hpa);
        unsafe {
            core::ptr::write_bytes(dst.as_mut_ptr::<u8>(), 0, 4096);
        }

        if enclave.module_size > 0 {
            let offset = i * 4096;
            let remain = enclave.module_size.saturating_sub(offset);
            let chunk = remain.min(4096);
            if chunk > 0 {
                let src = crate::memory::phys_to_virt(PhysAddr::new(enclave.module_phys + offset as u64));
                unsafe {
                    core::ptr::copy_nonoverlapping(src.as_ptr::<u8>(), dst.as_mut_ptr::<u8>(), chunk);
                }
            }
        }

        let gpa = PhysAddr::new(base_gpa + (i as u64) * 4096);
        enclave.ept.map(gpa, hpa, page_rwx);
    }

    enclave.entry_rip = base_gpa;
    enclave.entry_rsp = base_gpa + (pages as u64) * 4096 + 4096;
}

fn launch_first_enclave(enclave_id: u32, virt_provider: &mut dyn VirtualizationProvider) {
    let (guest_rip, guest_rsp, vpid) = {
        let g = get_manager();
        let e = g.as_ref().unwrap().get_enclave(enclave_id).unwrap();
        (e.entry_rip, e.entry_rsp, e.id as u16)
    };
    
    {
        let mut manager_guard = get_manager();
        let manager = manager_guard.as_mut().unwrap();
        if let Some(enclave) = manager.get_enclave_mut(enclave_id) {
            let eptp = enclave.ept.pml4_address().as_u64() | (3 << 3) | 6;
            virt_provider.prepare_guest(
                enclave.vmcs_phys_addr,
                guest_rip,
                guest_rsp,
                eptp,
                vpid,
                enclave.pml_buffer_phys_addr,
            );
            
            enclave.launched = true;
            enclave.state = EnclaveState::Running;
            percpu::set_active_vmcs(enclave.vmcs_phys_addr.as_u64());
        }
        percpu::set_current_enclave_id(Some(enclave_id));
    }
    
    crate::mark_boot_success!(crate::boot_validator::BootPhase::FirstGuest);
    virt_provider.launch_guest();
}