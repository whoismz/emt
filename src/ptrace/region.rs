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

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== TrackedRegion Tests ====================

    #[test]
    fn test_tracked_region_new() {
        let region = TrackedRegion::new(
            0x1000,
            0x2000,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            RegionSource::Mmap,
        );

        assert_eq!(region.addr, 0x1000);
        assert_eq!(region.len, 0x2000);
        assert_eq!(region.original_prot, PROT_READ | PROT_WRITE | PROT_EXEC);
        assert_eq!(region.current_prot, PROT_READ | PROT_WRITE);
        assert_eq!(region.state, RegionState::Writable);
        assert_eq!(region.source, RegionSource::Mmap);
        assert_eq!(region.exec_capture_count, 0);
        assert_eq!(region.write_fault_count, 0);
    }

    #[test]
    fn test_tracked_region_from_mprotect() {
        let region = TrackedRegion::from_mprotect(0x3000, 0x1000, PROT_READ | PROT_EXEC);

        assert_eq!(region.addr, 0x3000);
        assert_eq!(region.len, 0x1000);
        assert_eq!(region.source, RegionSource::Mprotect);
    }

    #[test]
    fn test_tracked_region_end_addr() {
        let region = TrackedRegion::new(0x1000, 0x2000, PROT_READ | PROT_EXEC, RegionSource::Mmap);

        assert_eq!(region.end_addr(), 0x3000);
    }

    #[test]
    fn test_tracked_region_end_addr_overflow() {
        let region = TrackedRegion::new(
            u64::MAX - 0x100,
            0x200,
            PROT_READ | PROT_EXEC,
            RegionSource::Mmap,
        );

        // Should saturate instead of overflow
        assert_eq!(region.end_addr(), u64::MAX);
    }

    #[test]
    fn test_tracked_region_contains() {
        let region = TrackedRegion::new(0x1000, 0x2000, PROT_READ | PROT_EXEC, RegionSource::Mmap);

        // Inside region
        assert!(region.contains(0x1000)); // Start
        assert!(region.contains(0x2000)); // Middle
        assert!(region.contains(0x2FFF)); // Just before end

        // Outside region
        assert!(!region.contains(0x0FFF)); // Before start
        assert!(!region.contains(0x3000)); // At end (exclusive)
        assert!(!region.contains(0x4000)); // After end
    }

    #[test]
    fn test_tracked_region_overlaps() {
        let region = TrackedRegion::new(0x2000, 0x2000, PROT_READ | PROT_EXEC, RegionSource::Mmap);
        // Region spans 0x2000 - 0x4000

        // Overlapping cases
        assert!(region.overlaps(0x1000, 0x2000)); // Ends at region start
        assert!(region.overlaps(0x3000, 0x2000)); // Starts in middle
        assert!(region.overlaps(0x2500, 0x1000)); // Fully inside
        assert!(region.overlaps(0x1000, 0x5000)); // Fully contains region

        // Non-overlapping cases
        assert!(!region.overlaps(0x0000, 0x1000)); // Completely before
        assert!(!region.overlaps(0x4000, 0x1000)); // Starts at region end
        assert!(!region.overlaps(0x5000, 0x1000)); // Completely after
    }

    #[test]
    fn test_tracked_region_is_writable() {
        let mut region = TrackedRegion::new(
            0x1000,
            0x1000,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            RegionSource::Mmap,
        );

        assert!(region.is_writable());
        assert!(!region.is_executable());

        region.transition_to_executable();

        assert!(!region.is_writable());
        assert!(region.is_executable());
    }

    #[test]
    fn test_tracked_region_determine_fault_type() {
        let mut region = TrackedRegion::new(
            0x1000,
            0x1000,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            RegionSource::Mmap,
        );

        // Initially writable, so fault would be execution attempt
        assert_eq!(region.determine_fault_type(), FaultType::ExecutionAttempt);

        region.transition_to_executable();

        // Now executable, so fault would be write attempt
        assert_eq!(region.determine_fault_type(), FaultType::WriteAttempt);
    }

    #[test]
    fn test_tracked_region_transition_to_executable() {
        let mut region = TrackedRegion::new(
            0x1000,
            0x1000,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            RegionSource::Mmap,
        );

        let new_prot = region.transition_to_executable();

        assert_eq!(new_prot, PROT_READ | PROT_EXEC);
        assert_eq!(region.state, RegionState::Executable);
        assert_eq!(region.current_prot, PROT_READ | PROT_EXEC);
        assert_eq!(region.exec_capture_count, 1);
    }

    #[test]
    fn test_tracked_region_transition_to_writable() {
        let mut region = TrackedRegion::new(
            0x1000,
            0x1000,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            RegionSource::Mmap,
        );
        region.transition_to_executable();

        let new_prot = region.transition_to_writable();

        assert_eq!(new_prot, PROT_READ | PROT_WRITE);
        assert_eq!(region.state, RegionState::Writable);
        assert_eq!(region.current_prot, PROT_READ | PROT_WRITE);
        assert_eq!(region.write_fault_count, 1);
    }

    #[test]
    fn test_tracked_region_wx_cycle() {
        let mut region = TrackedRegion::new(
            0x1000,
            0x1000,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            RegionSource::Mmap,
        );

        // Simulate W-X cycles
        for i in 1..=3 {
            region.transition_to_executable();
            assert_eq!(region.exec_capture_count, i);

            region.transition_to_writable();
            assert_eq!(region.write_fault_count, i);
        }

        assert_eq!(region.exec_capture_count, 3);
        assert_eq!(region.write_fault_count, 3);
    }

    // ==================== RegionTracker Tests ====================

    #[test]
    fn test_region_tracker_new() {
        let tracker = RegionTracker::new();

        assert!(tracker.regions().is_empty());
    }

    #[test]
    fn test_region_tracker_add_and_find() {
        let mut tracker = RegionTracker::new();
        let region = TrackedRegion::new(
            0x1000,
            0x2000,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            RegionSource::Mmap,
        );

        tracker.add(region);

        assert_eq!(tracker.regions().len(), 1);

        // Find within region
        assert!(tracker.find(0x1000).is_some());
        assert!(tracker.find(0x2000).is_some());
        assert!(tracker.find(0x2FFF).is_some());

        // Find outside region
        assert!(tracker.find(0x0FFF).is_none());
        assert!(tracker.find(0x3000).is_none());
    }

    #[test]
    fn test_region_tracker_find_mut() {
        let mut tracker = RegionTracker::new();
        let region = TrackedRegion::new(
            0x1000,
            0x1000,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            RegionSource::Mmap,
        );

        tracker.add(region);

        // Modify via find_mut
        if let Some(r) = tracker.find_mut(0x1500) {
            r.transition_to_executable();
        }

        // Verify modification
        let found = tracker.find(0x1500).unwrap();
        assert_eq!(found.state, RegionState::Executable);
        assert_eq!(found.exec_capture_count, 1);
    }

    #[test]
    fn test_region_tracker_find_executable_mut() {
        let mut tracker = RegionTracker::new();

        let mut region1 = TrackedRegion::new(
            0x1000,
            0x1000,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            RegionSource::Mmap,
        );
        region1.transition_to_executable();

        let region2 = TrackedRegion::new(
            0x2000,
            0x1000,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            RegionSource::Mmap,
        );
        // region2 stays writable

        tracker.add(region1);
        tracker.add(region2);

        // Should find executable region
        assert!(tracker.find_executable_mut(0x1500).is_some());

        // Should not find writable region via find_executable_mut
        assert!(tracker.find_executable_mut(0x2500).is_none());
    }

    #[test]
    fn test_region_tracker_multiple_regions() {
        let mut tracker = RegionTracker::new();

        tracker.add(TrackedRegion::new(
            0x1000,
            0x1000,
            PROT_READ | PROT_EXEC,
            RegionSource::Mmap,
        ));
        tracker.add(TrackedRegion::new(
            0x3000,
            0x1000,
            PROT_READ | PROT_EXEC,
            RegionSource::Mmap,
        ));
        tracker.add(TrackedRegion::new(
            0x5000,
            0x1000,
            PROT_READ | PROT_EXEC,
            RegionSource::Mprotect,
        ));

        assert_eq!(tracker.regions().len(), 3);

        assert!(tracker.find(0x1500).is_some());
        assert!(tracker.find(0x2500).is_none()); // Gap between regions
        assert!(tracker.find(0x3500).is_some());
        assert!(tracker.find(0x4500).is_none()); // Gap between regions
        assert!(tracker.find(0x5500).is_some());
    }

    #[test]
    fn test_region_tracker_remove_overlapping() {
        let mut tracker = RegionTracker::new();

        tracker.add(TrackedRegion::new(
            0x1000,
            0x1000,
            PROT_READ | PROT_EXEC,
            RegionSource::Mmap,
        ));
        tracker.add(TrackedRegion::new(
            0x3000,
            0x1000,
            PROT_READ | PROT_EXEC,
            RegionSource::Mmap,
        ));
        tracker.add(TrackedRegion::new(
            0x5000,
            0x1000,
            PROT_READ | PROT_EXEC,
            RegionSource::Mmap,
        ));

        assert_eq!(tracker.regions().len(), 3);

        // Remove region at 0x3000
        tracker.remove_overlapping(0x3000, 0x1000);

        assert_eq!(tracker.regions().len(), 2);
        assert!(tracker.find(0x1500).is_some());
        assert!(tracker.find(0x3500).is_none()); // Removed
        assert!(tracker.find(0x5500).is_some());
    }

    #[test]
    fn test_region_tracker_remove_overlapping_multiple() {
        let mut tracker = RegionTracker::new();

        tracker.add(TrackedRegion::new(
            0x1000,
            0x1000,
            PROT_READ | PROT_EXEC,
            RegionSource::Mmap,
        ));
        tracker.add(TrackedRegion::new(
            0x2000,
            0x1000,
            PROT_READ | PROT_EXEC,
            RegionSource::Mmap,
        ));
        tracker.add(TrackedRegion::new(
            0x3000,
            0x1000,
            PROT_READ | PROT_EXEC,
            RegionSource::Mmap,
        ));

        assert_eq!(tracker.regions().len(), 3);

        // Remove with range that overlaps multiple regions
        tracker.remove_overlapping(0x1500, 0x2000);

        // Should remove regions at 0x1000, 0x2000, and 0x3000 (all overlap with 0x1500-0x3500)
        assert_eq!(tracker.regions().len(), 0);
    }

    #[test]
    fn test_region_tracker_remove_overlapping_no_match() {
        let mut tracker = RegionTracker::new();

        tracker.add(TrackedRegion::new(
            0x1000,
            0x1000,
            PROT_READ | PROT_EXEC,
            RegionSource::Mmap,
        ));

        // Remove non-overlapping range
        tracker.remove_overlapping(0x5000, 0x1000);

        assert_eq!(tracker.regions().len(), 1);
    }

    #[test]
    fn test_region_state_equality() {
        assert_eq!(RegionState::Writable, RegionState::Writable);
        assert_eq!(RegionState::Executable, RegionState::Executable);
        assert_ne!(RegionState::Writable, RegionState::Executable);
    }

    #[test]
    fn test_fault_type_equality() {
        assert_eq!(FaultType::ExecutionAttempt, FaultType::ExecutionAttempt);
        assert_eq!(FaultType::WriteAttempt, FaultType::WriteAttempt);
        assert_ne!(FaultType::ExecutionAttempt, FaultType::WriteAttempt);
    }

    #[test]
    fn test_region_source_equality() {
        assert_eq!(RegionSource::Mmap, RegionSource::Mmap);
        assert_eq!(RegionSource::Mprotect, RegionSource::Mprotect);
        assert_ne!(RegionSource::Mmap, RegionSource::Mprotect);
    }
}
