// src/memory/boot.rs
use multiboot2::BootInformation;
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealmKind {
    Micro = 0,
    Macro = 1,
}

#[derive(Debug, Clone, Copy)]
pub struct GuestImageSpec {
    pub module_start: u64,
    pub module_size: usize,
    pub load_gpa: u64,
    pub realm_kind: RealmKind,
}

static GUEST_SPECS: Mutex<[Option<GuestImageSpec>; 8]> = Mutex::new([None; 8]);
pub static GUEST_MODULE: Mutex<Option<(u64, usize)>> = Mutex::new(None);

fn parse_guest_cmdline(cmdline: &str) -> Option<(RealmKind, u64)> {
    let t = cmdline.trim();
    if t == "guest" || t == "macro" {
        let kind = if t == "guest" { RealmKind::Micro } else { RealmKind::Macro };
        return Some((kind, 0x8000));
    }

    if let Some(rest) = t.strip_prefix("guest:") {
        let gpa = u64::from_str_radix(rest.trim().trim_start_matches("0x"), 16).ok()?;
        return Some((RealmKind::Micro, gpa));
    }

    if let Some(rest) = t.strip_prefix("macro:") {
        let gpa = u64::from_str_radix(rest.trim().trim_start_matches("0x"), 16).ok()?;
        return Some((RealmKind::Macro, gpa));
    }

    None
}

pub fn parse_multiboot_modules(boot_info: &BootInformation) {
    let mut slots = [None; 8];
    let mut n = 0usize;
    for module in boot_info.module_tags() {
        if let Some((realm_kind, load_gpa)) = parse_guest_cmdline(module.cmdline().unwrap_or("")) {
            let start = module.start_address() as u64;
            let size = (module.end_address() - module.start_address()) as usize;
            if n < 8 {
                slots[n] = Some(GuestImageSpec {
                    module_start: start,
                    module_size: size,
                    load_gpa,
                    realm_kind,
                });
                n += 1;
            }
        }
    }
    *GUEST_SPECS.lock() = slots;
    if let Some(first) = slots.into_iter().flatten().next() {
        *GUEST_MODULE.lock() = Some((first.module_start, first.module_size));
    }
}

pub fn guest_image_specs() ->[Option<GuestImageSpec>; 8] {
    *GUEST_SPECS.lock()
}