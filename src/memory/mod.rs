// src/memory/mod.rs
pub mod boot;
pub mod buddy;
pub mod ept;
pub mod frame;
pub mod heap;
pub mod utils;

pub use boot::{GuestImageSpec, RealmKind, guest_image_specs}; // 移除 GUEST_MODULE 导入
pub use frame::{allocate_frame, deallocate_frame, phys_to_virt};
pub use heap::HeapAllocator;

pub fn init(multiboot_info_addr: usize) {
    crate::log_debug!("加载系统引导架构信息块...");
    let boot_info = unsafe { 
        multiboot2::BootInformation::load(multiboot_info_addr as *const multiboot2::BootInformationHeader)
            .expect("数据毁损: 无法解析 Multiboot2 内存头") 
    };
    
    let memory_map_tag = boot_info.memory_map_tag()
        .expect("启动中止: 微架构固件未向内核输送可用物理内存拓扑记录");

    boot::parse_multiboot_modules(&boot_info);

    crate::log_debug!("初始化核心资源底座: 构建伙伴系统分配树...");
    frame::init(&memory_map_tag);

    crate::log_debug!("挂载系统通用动态存储空间...");
    heap::init(&memory_map_tag);

    crate::log_info!("物理内存路由及地址空间总控部署完成");
}