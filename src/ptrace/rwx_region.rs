//! Tracked RWX memory regions
use std::time::Instant;

/// Protection flags
pub const PROT_READ: u64 = 0x1;
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC: u64 = 0x4;

/// State of a tracked RWX region
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionState {
    /// Region was created with RW (exec stripped), waiting for execution attempt
    WaitingForExec,
    /// First execution attempt was caught and handled, region now has RX
    ExecutionHandled,
}

/// Represents a memory region where we stripped execute permission
#[derive(Debug, Clone)]
pub struct RwxRegion {
    pub addr: u64,
    pub len: u64,
    pub original_prot: u64,
    pub modified_prot: u64,
    pub state: RegionState,
    pub created_at: Instant,  // Timestamp when this region was created
    pub source: RegionSource, // Source of the region (mmap or mprotect)
}

/// How the region was created
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionSource {
    /// Created via mmap syscall
    Mmap,
    /// Created via mprotect syscall
    Mprotect,
}

impl RwxRegion {
    /// Creates a new tracked region
    pub fn new(addr: u64, len: u64, original_prot: u64, source: RegionSource) -> Self {
        // Strip EXEC from protection
        let modified_prot = original_prot & !PROT_EXEC;

        Self {
            addr,
            len,
            original_prot,
            modified_prot,
            state: RegionState::WaitingForExec,
            created_at: Instant::now(),
            source,
        }
    }

    /// Creates a region from mmap parameters.
    /// The addr will be updated later when we get the syscall return value.
    pub fn from_mmap_pending(len: u64, original_prot: u64) -> Self {
        Self::new(0, len, original_prot, RegionSource::Mmap)
    }

    /// Creates a region from mprotect parameters.
    pub fn from_mprotect(addr: u64, len: u64, original_prot: u64) -> Self {
        Self::new(addr, len, original_prot, RegionSource::Mprotect)
    }

    /// Updates the address (used after mmap syscall returns)
    pub fn set_addr(&mut self, addr: u64) {
        self.addr = addr;
    }

    /// Returns the end address (exclusive) of the region
    pub fn end_addr(&self) -> u64 {
        self.addr.saturating_add(self.len)
    }

    /// Checks if a given address falls within this region
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.addr && addr < self.end_addr()
    }

    /// Checks if this region overlaps with another address range
    pub fn overlaps(&self, other_addr: u64, other_len: u64) -> bool {
        let other_end = other_addr.saturating_add(other_len);
        self.addr < other_end && other_addr < self.end_addr()
    }

    /// Checks if the region is waiting for an execution attempt
    pub fn is_waiting_for_exec(&self) -> bool {
        self.state == RegionState::WaitingForExec
    }

    /// Marks the region as having had its execution handled
    pub fn mark_execution_handled(&mut self) {
        self.state = RegionState::ExecutionHandled;
    }

    /// Returns the protection to restore for execution
    pub fn exec_restore_prot(&self) -> u64 {
        PROT_READ | PROT_EXEC
    }

    /// Checks if the original protection was RWX
    pub fn was_rwx(&self) -> bool {
        let rwx = PROT_READ | PROT_WRITE | PROT_EXEC;
        (self.original_prot & rwx) == rwx
    }

    /// Returns true if original protection included WRITE and EXEC
    pub fn had_write_and_exec(&self) -> bool {
        (self.original_prot & PROT_WRITE) != 0 && (self.original_prot & PROT_EXEC) != 0
    }
}

/// Collection of tracked RWX regions
#[derive(Debug, Default)]
pub struct RwxRegionTracker {
    regions: Vec<RwxRegion>,
}

impl RwxRegionTracker {
    /// Creates a new empty tracker
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    /// Adds a new region to track
    pub fn add(&mut self, region: RwxRegion) {
        self.regions.push(region);
    }

    /// Finds a region containing the given address that is waiting for execution
    pub fn find_waiting_region(&self, addr: u64) -> Option<&RwxRegion> {
        self.regions
            .iter()
            .find(|r| r.contains(addr) && r.is_waiting_for_exec())
    }

    /// Finds a mutable reference to a region containing the given address
    pub fn find_waiting_region_mut(&mut self, addr: u64) -> Option<&mut RwxRegion> {
        self.regions
            .iter_mut()
            .find(|r| r.contains(addr) && r.is_waiting_for_exec())
    }

    /// Gets all regions
    pub fn regions(&self) -> &[RwxRegion] {
        &self.regions
    }

    /// Gets the number of tracked regions
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Checks if there are no tracked regions
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Removes regions that overlap with a given address range
    pub fn remove_overlapping(&mut self, addr: u64, len: u64) {
        self.regions.retain(|r| !r.overlaps(addr, len));
    }

    /// Gets the last added region
    pub fn last_mut(&mut self) -> Option<&mut RwxRegion> {
        self.regions.last_mut()
    }
}
