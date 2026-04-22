/* src/fusion/mod.rs */
pub mod virtio;

use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FusionBackendKind {
    VirtioNet = 0,
    VirtioBlock = 1,
}

#[derive(Debug, Clone, Copy)]
pub struct FusionRegistration {
    #[allow(dead_code)]
    pub kind: FusionBackendKind,
    #[allow(dead_code)]
    pub service_enclave_id: u32,
}

const MAX_REG: usize = 4;

pub struct FusionHub {
    entries: [Option<FusionRegistration>; MAX_REG],
}

impl FusionHub {
    pub const fn new() -> Self {
        const E: Option<FusionRegistration> = None;
        Self { entries: [E; MAX_REG] }
    }

    pub fn register(&mut self, kind: FusionBackendKind, service_enclave_id: u32) -> Result<(), ()> {
        for slot in &mut self.entries {
            if slot.is_none() {
                *slot = Some(FusionRegistration {
                    kind,
                    service_enclave_id,
                });
                crate::log_info!("Fusion 路由注册: {:?} 指向服务域 {}", kind, service_enclave_id);
                return Ok(());
            }
        }
        Err(())
    }
}

static HUB: Mutex<FusionHub> = Mutex::new(FusionHub::new());

pub fn init() {
    crate::log_info!("Fusion 桥接中心就绪 (最大支持 {} 个后端)，包含 VirtIO-MSB 解析器", MAX_REG);
}

pub fn hub() -> spin::MutexGuard<'static, FusionHub> {
    HUB.lock()
}