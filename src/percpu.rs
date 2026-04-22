/* src/percpu.rs */
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

const MAX_CORES: usize = 256;
const EMERGENCY_STACK_SIZE: usize = 4096 * 4;

#[derive(Debug, Clone, Copy)]
pub struct PerCoreState {
    pub current_enclave_id: Option<u32>,
    pub active_vmcs_ptr: u64,
    pub apic_id: u32,
    pub is_idle: bool,
    pub core_id: usize,
}

impl PerCoreState {
    pub const fn new() -> Self {
        Self {
            current_enclave_id: None,
            active_vmcs_ptr: 0,
            apic_id: 0,
            is_idle: true,
            core_id: 0,
        }
    }
}

#[repr(align(64))]
struct AlignedPerCoreData {
    data: UnsafeCell<PerCoreState>,
    emergency_stack:[u8; EMERGENCY_STACK_SIZE],
}

unsafe impl Sync for AlignedPerCoreData {}

static PER_CORE_DATA: [AlignedPerCoreData; MAX_CORES] =[const {
    AlignedPerCoreData {
        data: UnsafeCell::new(PerCoreState::new()),
        emergency_stack:[0; EMERGENCY_STACK_SIZE],
    }
}; MAX_CORES];

static NEXT_CORE_ID: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
fn get_current_cpu_id() -> usize {
    let id = NEXT_CORE_ID.fetch_add(1, Ordering::Relaxed);
    id % MAX_CORES
}

pub fn init() {
    for i in 0..MAX_CORES {
        unsafe {
            let state = &mut *PER_CORE_DATA[i].data.get();
            state.core_id = i;
        }
    }
    crate::log_debug!("每核数据结构初始化完毕 (支持上限: {} 核)", MAX_CORES);
}

#[inline(always)]
pub fn get_core_id() -> usize {
    (crate::arch::x86_64::apic::local_apic_id() & (MAX_CORES as u32 - 1)) as usize
}

pub fn get_state() -> &'static mut PerCoreState {
    unsafe { &mut *PER_CORE_DATA[get_core_id()].data.get() }
}

pub fn get_state_for_core(core_id: usize) -> &'static mut PerCoreState {
    unsafe { &mut *PER_CORE_DATA[core_id].data.get() }
}

pub fn get_current_enclave_id() -> Option<u32> {
    get_state().current_enclave_id
}

pub fn set_current_enclave_id(id: Option<u32>) {
    get_state().current_enclave_id = id;
}

pub fn set_active_vmcs(ptr: u64) {
    get_state().active_vmcs_ptr = ptr;
}

pub fn get_active_vmcs() -> u64 {
    get_state().active_vmcs_ptr
}

pub fn mark_core_idle(is_idle: bool) {
    get_state().is_idle = is_idle;
}