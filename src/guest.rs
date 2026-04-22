core::arch::global_asm!(
    ".section .guest_code, \"ax\"",
    ".global guest_entry",
    "guest_entry:",
    "hlt",
    "jmp guest_entry"
);

extern "C" {
    pub fn guest_entry();
}