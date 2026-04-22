// src/arch/x86_64/iommu/audit.rs

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DmaAuditRecord {
    pub op: DmaAuditOp,
    pub bdf: u16,
    pub domain_id: u32,
    pub ok: bool,
    pub fault_gpa: u64,
    pub fault_flags: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DmaAuditOp {
    Register,
    RemapHook,
    Invalidate,
    Teardown,
    Reclaim,
    DmaFault,
}

pub const AUDIT_RING: usize = 32;

pub struct AuditLog {
    records: [DmaAuditRecord; AUDIT_RING],
    head: usize,
}

impl AuditLog {
    pub const fn new() -> Self {
        Self {
            records:[DmaAuditRecord {
                op: DmaAuditOp::Register,
                bdf: 0,
                domain_id: 0,
                ok: false,
                fault_gpa: 0,
                fault_flags: 0,
            }; AUDIT_RING],
            head: 0,
        }
    }

    pub fn push(&mut self, mut rec: DmaAuditRecord) {
        if rec.op != DmaAuditOp::DmaFault {
            rec.fault_gpa = 0;
            rec.fault_flags = 0;
        }
        let i = self.head % AUDIT_RING;
        self.records[i] = rec;
        self.head = self.head.wrapping_add(1);
    }

    pub fn snapshot(&self) ->[DmaAuditRecord; AUDIT_RING] {
        self.records
    }

    pub fn dump_serial(&self, max_entries: usize) {
        let n = max_entries.min(AUDIT_RING);
        if n == 0 {
            return;
        }
        crate::serial_println!("[IOMMU] --- audit ring (last {} ops) ---", n);
        for k in 0..n {
            let idx = self.head.wrapping_sub(1 + k as usize) % AUDIT_RING;
            let rec = self.records[idx];
            let op = match rec.op {
                DmaAuditOp::Register => "reg",
                DmaAuditOp::RemapHook => "remap",
                DmaAuditOp::Invalidate => "inval",
                DmaAuditOp::Teardown => "teardown",
                DmaAuditOp::Reclaim => "reclaim",
                DmaAuditOp::DmaFault => "FAULT",
            };
            crate::serial_println!(
                "[IOMMU]  #{:02} {:7} BDF={:#06x} domain={} ok={} GPA={:#x}",
                idx, op, rec.bdf, rec.domain_id, rec.ok, rec.fault_gpa
            );
        }
        crate::serial_println!("[IOMMU] --- end audit ---");
    }
}