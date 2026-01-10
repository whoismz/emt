//! Tracked memory regions with W^X enforcement.

use std::time::Instant;

pub const PROT_READ: u64 = 0x1;
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC: u64 = 0x4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionState {
    /// Region has RW permissions, waiting for execution attempt.
    Writable,
    /// Region has RX permissions, waiting for write attempt.
    Executable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultType {
    ExecutionAttempt,
    WriteAttempt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionSource {
    Mmap,
    Mprotect,
}

#[derive(Debug, Clone)]
pub struct TrackedRegion {
    pub addr: u64,
    pub len: u64,
    pub original_prot: u64,
    pub current_prot: u64,
    pub state: RegionState,
    pub source: RegionSource,
    pub created_at: Instant,
    pub exec_capture_count: u32,
    pub write_fault_count: u32,
}

impl TrackedRegion {
    pub fn new(addr: u64, len: u64, original_prot: u64, source: RegionSource) -> Self {
        Self {
            addr,
            len,
            original_prot,
            current_prot: PROT_READ | PROT_WRITE,
            state: RegionState::Writable,
            source,
            created_at: Instant::now(),
            exec_capture_count: 0,
            write_fault_count: 0,
        }
    }

    pub fn from_mprotect(addr: u64, len: u64, original_prot: u64) -> Self {
        Self::new(addr, len, original_prot, RegionSource::Mprotect)
    }

    pub fn end_addr(&self) -> u64 {
        self.addr.saturating_add(self.len)
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.addr && addr < self.end_addr()
    }

    pub fn overlaps(&self, other_addr: u64, other_len: u64) -> bool {
        let other_end = other_addr.saturating_add(other_len);
        self.addr < other_end && other_addr < self.end_addr()
    }

    pub fn is_writable(&self) -> bool {
        self.state == RegionState::Writable
    }

    pub fn is_executable(&self) -> bool {
        self.state == RegionState::Executable
    }

    pub fn determine_fault_type(&self) -> FaultType {
        match self.state {
            RegionState::Writable => FaultType::ExecutionAttempt,
            RegionState::Executable => FaultType::WriteAttempt,
        }
    }

    /// Transitions from Writable to Executable state (W→X).
    pub fn transition_to_executable(&mut self) -> u64 {
        self.state = RegionState::Executable;
        self.current_prot = PROT_READ | PROT_EXEC;
        self.exec_capture_count += 1;

        log::debug!(
            "Region 0x{:x}-0x{:x}: W→X (capture #{})",
            self.addr,
            self.end_addr(),
            self.exec_capture_count
        );

        self.current_prot
    }

    /// Transitions from Executable to Writable state (X→W).
    pub fn transition_to_writable(&mut self) -> u64 {
        self.state = RegionState::Writable;
        self.current_prot = PROT_READ | PROT_WRITE;
        self.write_fault_count += 1;

        log::debug!(
            "Region 0x{:x}-0x{:x}: X→W (write fault #{})",
            self.addr,
            self.end_addr(),
            self.write_fault_count
        );

        self.current_prot
    }
}

#[derive(Debug, Default)]
pub struct RegionTracker {
    regions: Vec<TrackedRegion>,
}

impl RegionTracker {
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    pub fn add(&mut self, region: TrackedRegion) {
        log::debug!(
            "Tracking region: 0x{:x}-0x{:x}, source={:?}",
            region.addr,
            region.end_addr(),
            region.source
        );
        self.regions.push(region);
    }

    pub fn find(&self, addr: u64) -> Option<&TrackedRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    pub fn find_mut(&mut self, addr: u64) -> Option<&mut TrackedRegion> {
        self.regions.iter_mut().find(|r| r.contains(addr))
    }

    pub fn find_executable_mut(&mut self, addr: u64) -> Option<&mut TrackedRegion> {
        self.regions
            .iter_mut()
            .find(|r| r.contains(addr) && r.is_executable())
    }

    pub fn regions(&self) -> &[TrackedRegion] {
        &self.regions
    }

    pub fn remove_overlapping(&mut self, addr: u64, len: u64) {
        let before = self.regions.len();
        self.regions.retain(|r| !r.overlaps(addr, len));
        let removed = before - self.regions.len();
        if removed > 0 {
            log::debug!("Removed {} region(s) at 0x{:x}", removed, addr);
        }
    }
}
