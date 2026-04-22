#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

#[inline(always)]
unsafe fn hypercall(nr: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> (u64, u64, u64) {
    let rax: u64;
    let rbx: u64;
    let rcx: u64;
    asm!(
        "vmcall",
        inout("rcx") nr => rcx,
        in("rdx") arg1,
        in("rsi") arg2,
        in("rdi") arg3,
        in("r8")  arg4,
        in("r9")  arg5,
        lateout("rax") rax,
        lateout("rbx") rbx,
        options(nostack)
    );
    (rax, rbx, rcx)
}

struct DebugOut;

impl core::fmt::Write for DebugOut {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        unsafe {
            let mut ptr = s.as_ptr() as u64;
            let mut len = s.len() as u64;
            while len > 0 {
                let chunk = if len > 512 { 512 } else { len };
                hypercall(0xFF, ptr, chunk, 0, 0, 0);
                ptr += chunk;
                len -= chunk;
            }
        }
        Ok(())
    }
}

macro_rules! println {
    ($($arg:tt)*) => {
        let _ = core::fmt::Write::write_fmt(&mut DebugOut, format_args!($($arg)*));
        let _ = core::fmt::Write::write_str(&mut DebugOut, "\n");
    };
}

#[no_mangle]
#[link_section = ".text.entry"]
pub extern "C" fn _start() -> ! {
    println!("[MicroDomain] Init domain started at GPA 0x8000");

    let (status, rbx, _) = unsafe { hypercall(0x06, 0, 0, 0, 0, 0) };
    if status == 0 {
        let magic = rbx >> 32;
        let api = rbx & 0xFFFFFFFF;
        let mut magic_chars = [0u8; 4];
        magic_chars[0] = (magic & 0xFF) as u8;
        magic_chars[1] = ((magic >> 8) & 0xFF) as u8;
        magic_chars[2] = ((magic >> 16) & 0xFF) as u8;
        magic_chars[3] = ((magic >> 24) & 0xFF) as u8;
        if let Ok(magic_str) = core::str::from_utf8(&magic_chars) {
            println!("[MicroDomain] Hypervisor Magic: '{}', API Level: {}", magic_str, api);
        }
    }

    let (status, caps, kind) = unsafe { hypercall(0x0D, 0, 0, 0, 0, 0) };
    if status == 0 {
        println!("[MicroDomain] Realm Kind: {} (0=Micro, 1=Macro)", kind);
        println!("[MicroDomain] Capability Bitmap: {:#010x}", caps);
    }

    let (status, _, _) = unsafe { hypercall(0x0B, 0, 0, 0, 0, 0) };
    if status == 0 {
        println!("[MicroDomain] Fusion Backend (VirtioNet) Registered Successfully");
    }

    let (status, _, _) = unsafe { hypercall(0x08, 0, 0xA1B2C3D4, 0x8000, 0, 0) };
    if status == 0 {
        println!("[MicroDomain] MMDL Published at slot 0");
    }

    println!("[MicroDomain] Running TSC Microbench (100000 iterations)...");
    unsafe { hypercall(0x0A, 100000, 0, 0, 0, 0) };

    println!("[MicroDomain] Pulling recent IOMMU audit logs to serial:");
    unsafe { hypercall(0x42, 1, 5, 0, 0, 0) };

    let bdf = (0 << 8) | (0x1F << 3) | 0;
    let mmio_gpa = 0xFE00_0000u64;
    let size = 4096u64;
    let (status, _, _) = unsafe { hypercall(0x03, bdf, mmio_gpa, size, 0, 0) };
    if status == 0 {
        println!("[MicroDomain] MapDevice successful for BDF {:#06x} at GPA {:#x}", bdf, mmio_gpa);
    } else {
        println!("[MicroDomain] MapDevice failed for BDF {:#06x} (status: {})", bdf, status);
    }

    let batch: [(u64, u64, u64); 1] = [
        (0x9000, 0xA000, 1 | 2 | 48)
    ];
    let (status, _, _) = unsafe { hypercall(0x07, 1, 2, batch.as_ptr() as u64, 1, 0) };
    println!("[MicroDomain] PageTransferBatch status/transferred: {}", status);

    let (status, state, _) = unsafe { hypercall(0x02, 2, 0, 0, 0, 0) };
    println!("[MicroDomain] Enclave 2 State: {} (status: {})", state, status);

    println!("[MicroDomain] Initial setup complete. Yielding execution...");
    unsafe { hypercall(0x04, 0, 0, 0, 0, 0) };

    println!("[MicroDomain] Resumed execution. Halting.");
    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("[MicroDomain] PANIC: {}", info);
    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}