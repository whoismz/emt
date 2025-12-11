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
    /// Execution attempt was caught, region now has RX, waiting for write transition
    Executable,
    /// Region was changed back to writable (RW), waiting for next execution attempt
    /// This enables the X->W->X->W... cycle detection
    WritableAgain,
}

/// Represents a memory region where we stripped execute permission
#[derive(Debug, Clone)]
pub struct RwxRegion {
    pub addr: u64,
    pub len: u64,
    pub original_prot: u64,
    pub modified_prot: u64,
    pub current_prot: u64,
    pub state: RegionState,
    pub created_at: Instant,
    pub last_transition_at: Instant,
    pub source: RegionSource,
    /// Number of times execution was captured for this region (supports X->W->X->W... cycles)
    pub exec_capture_count: u32,
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
        let now = Instant::now();

        Self {
            addr,
            len,
            original_prot,
            modified_prot,
            current_prot: modified_prot,
            state: RegionState::WaitingForExec,
            created_at: now,
            last_transition_at: now,
            source,
            exec_capture_count: 0,
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
    /// This is true both for initial WaitingForExec state and WritableAgain state
    pub fn is_waiting_for_exec(&self) -> bool {
        matches!(
            self.state,
            RegionState::WaitingForExec | RegionState::WritableAgain
        )
    }

    /// Checks if the region is currently executable (after execution was handled)
    pub fn is_executable(&self) -> bool {
        self.state == RegionState::Executable
    }

    /// Checks if the region is writable again after being executable
    pub fn is_writable_again(&self) -> bool {
        self.state == RegionState::WritableAgain
    }

    /// Marks the region as having had its execution handled
    /// Transitions: WaitingForExec -> Executable, WritableAgain -> Executable
    pub fn mark_execution_handled(&mut self) {
        self.state = RegionState::Executable;
        self.current_prot = PROT_READ | PROT_EXEC;
        self.last_transition_at = Instant::now();
        self.exec_capture_count += 1;
        log::debug!(
            "Region 0x{:x}-0x{:x} transitioned to Executable (capture #{})",
            self.addr,
            self.end_addr(),
            self.exec_capture_count
        );
    }

    /// Marks the region as writable again (for X->W->X->W... cycle support)
    /// Transitions: Executable -> WritableAgain
    /// This should be called when mprotect changes the region back to writable
    pub fn mark_writable_again(&mut self, new_prot: u64) {
        if self.state == RegionState::Executable {
            self.state = RegionState::WritableAgain;
            self.current_prot = new_prot & !PROT_EXEC; // Still strip exec
            self.last_transition_at = Instant::now();
            log::debug!(
                "Region 0x{:x}-0x{:x} transitioned to WritableAgain (cycle continues)",
                self.addr,
                self.end_addr()
            );
        }
    }

    /// Updates the region length if mprotect changes it
    pub fn update_len(&mut self, new_len: u64) {
        self.len = new_len;
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

    /// Returns the number of times execution has been captured for this region
    pub fn capture_count(&self) -> u32 {
        self.exec_capture_count
    }

    /// Returns the duration since this region was created
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Returns the duration since the last state transition
    pub fn time_since_last_transition(&self) -> std::time::Duration {
        self.last_transition_at.elapsed()
    }
}

/// Collection of tracked RWX regions
#[derive(Debug, Default)]
pub struct RwxRegionTracker {
    regions: Vec<RwxRegion>,
}

impl RwxRegionTracker {
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    /// Adds a new region to track
    pub fn add(&mut self, region: RwxRegion) {
        log::debug!(
            "Tracking new region: addr=0x{:x}, len=0x{:x}, source={:?}",
            region.addr,
            region.len,
            region.source
        );
        self.regions.push(region);
    }

    /// Finds a region containing the given address that is waiting for execution
    pub fn find_waiting_region(&self, addr: u64) -> Option<&RwxRegion> {
        self.regions
            .iter()
            .find(|r| r.contains(addr) && r.is_waiting_for_exec())
    }

    /// Finds a mutable reference to a region containing the given address that is waiting
    pub fn find_waiting_region_mut(&mut self, addr: u64) -> Option<&mut RwxRegion> {
        self.regions
            .iter_mut()
            .find(|r| r.contains(addr) && r.is_waiting_for_exec())
    }

    /// Finds any region containing the given address (regardless of state)
    pub fn find_region(&self, addr: u64) -> Option<&RwxRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    /// Finds a mutable reference to any region containing the given address
    pub fn find_region_mut(&mut self, addr: u64) -> Option<&mut RwxRegion> {
        self.regions.iter_mut().find(|r| r.contains(addr))
    }

    /// Finds an executable region that can be transitioned back to writable
    /// Used to detect X->W transitions in the cycle
    pub fn find_executable_region(&self, addr: u64) -> Option<&RwxRegion> {
        self.regions
            .iter()
            .find(|r| r.contains(addr) && r.is_executable())
    }

    /// Finds a mutable executable region for transitioning back to writable
    pub fn find_executable_region_mut(&mut self, addr: u64) -> Option<&mut RwxRegion> {
        self.regions
            .iter_mut()
            .find(|r| r.contains(addr) && r.is_executable())
    }

    /// Finds a region by exact address match (for mprotect handling)
    pub fn find_region_by_addr(&self, addr: u64, len: u64) -> Option<&RwxRegion> {
        self.regions.iter().find(|r| r.addr == addr && r.len == len)
    }

    /// Finds a mutable region by exact address match
    pub fn find_region_by_addr_mut(&mut self, addr: u64, len: u64) -> Option<&mut RwxRegion> {
        self.regions
            .iter_mut()
            .find(|r| r.addr == addr && r.len == len)
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
        let before = self.regions.len();
        self.regions.retain(|r| !r.overlaps(addr, len));
        let removed = before - self.regions.len();
        if removed > 0 {
            log::debug!(
                "Removed {} region(s) overlapping with 0x{:x}-0x{:x}",
                removed,
                addr,
                addr + len
            );
        }
    }

    /// Gets the last added region
    pub fn last_mut(&mut self) -> Option<&mut RwxRegion> {
        self.regions.last_mut()
    }

    /// Returns the total number of execution captures across all regions
    pub fn total_capture_count(&self) -> u32 {
        self.regions.iter().map(|r| r.exec_capture_count).sum()
    }

    /// Returns regions that have been through multiple X->W->X cycles
    pub fn cycled_regions(&self) -> Vec<&RwxRegion> {
        self.regions
            .iter()
            .filter(|r| r.exec_capture_count > 1)
            .collect()
    }

    /// Returns statistics about tracked regions
    pub fn stats(&self) -> TrackerStats {
        let total = self.regions.len();
        let waiting = self
            .regions
            .iter()
            .filter(|r| r.is_waiting_for_exec())
            .count();
        let executable = self.regions.iter().filter(|r| r.is_executable()).count();
        let writable_again = self
            .regions
            .iter()
            .filter(|r| r.is_writable_again())
            .count();
        let total_captures: u32 = self.regions.iter().map(|r| r.exec_capture_count).sum();
        let multi_cycle = self
            .regions
            .iter()
            .filter(|r| r.exec_capture_count > 1)
            .count();

        TrackerStats {
            total_regions: total,
            waiting_for_exec: waiting,
            executable: executable,
            writable_again: writable_again,
            total_captures: total_captures,
            multi_cycle_regions: multi_cycle,
        }
    }
}

/// Statistics about tracked regions
#[derive(Debug, Clone)]
pub struct TrackerStats {
    pub total_regions: usize,
    pub waiting_for_exec: usize,
    pub executable: usize,
    pub writable_again: usize,
    pub total_captures: u32,
    pub multi_cycle_regions: usize,
}

impl std::fmt::Display for TrackerStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Regions: {} total ({} waiting, {} executable, {} writable-again), {} captures, {} multi-cycle",
            self.total_regions,
            self.waiting_for_exec,
            self.executable,
            self.writable_again,
            self.total_captures,
            self.multi_cycle_regions
        )
    }
}
