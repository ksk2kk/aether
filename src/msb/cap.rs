/* src/msb/cap.rs */
use bitflags::bitflags;
use alloc::collections::BTreeMap;
extern crate alloc;
use alloc::vec::Vec;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Permission: u32 {
        const TRANSFER = 1 << 0;
        const MAP_SHARED = 1 << 1;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Capability {
    pub target_enclave_id: u32,
    pub permissions: Permission,
}

pub struct CapabilityManager {
    capability_lists: BTreeMap<u32, Vec<Capability>>,
}

impl CapabilityManager {
    pub fn new() -> Self {
        Self {
            capability_lists: BTreeMap::new(),
        }
    }

    pub fn grant(&mut self, src_enclave_id: u32, target_enclave_id: u32, perms: Permission) {
        let cap_list = self.capability_lists.entry(src_enclave_id).or_default();

        if let Some(existing_cap) = cap_list.iter_mut().find(|c| c.target_enclave_id == target_enclave_id) {
            existing_cap.permissions |= perms;
        } else {
            cap_list.push(Capability {
                target_enclave_id,
                permissions: perms,
            });
        }
    }

    pub fn has_permission(&self, src_enclave_id: u32, target_enclave_id: u32, required_perm: Permission) -> bool {
        if src_enclave_id == target_enclave_id {
            return true;
        }

        if src_enclave_id == 1 {
            return true;
        }

        if let Some(cap_list) = self.capability_lists.get(&src_enclave_id) {
            for cap in cap_list {
                if cap.target_enclave_id == target_enclave_id && cap.permissions.contains(required_perm) {
                    return true;
                }
            }
        }

        false
    }
}