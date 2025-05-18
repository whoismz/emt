use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug)]
pub enum EventType {
    Map,
    Unmap,
    Mprotect,
}

#[repr(C)]
pub struct Event {
    pub event_type: EventType,
    pub addr: usize,
    pub size: usize,
    pub timestamp: SystemTime,
    pub pid: i32,
    pub content: Option<Vec<u8>>,
}

impl Event {
    /// Creates a shutdown signal event
    pub fn shutdown() -> Self {
        Self {
            event_type: EventType::Unmap,
            addr: 0,
            size: 0,
            timestamp: SystemTime::now(),
            pid: 0,
            content: None,
        }
    }

    /// Checks if this is a shutdown event
    pub fn is_shutdown(&self) -> bool {
        self.pid == -1
    }

    /// Checks if this event contains the specified address
    pub fn contains_address(&self, addr: usize) -> bool {
        addr >= self.addr && addr < self.addr + self.size
    }

    /// Checks if this event overlaps with the given range
    pub fn overlaps(&self, addr: usize, size: usize) -> bool {
        let self_end = self.addr + self.size;
        let other_end = addr + size;
        self.addr < other_end && self_end > addr
    }

    /// Returns the end address of the memory region
    pub fn end_addr(&self) -> usize {
        self.addr + self.size
    }
}

pub struct Page {
    pub addr: usize,
    pub size: usize,
    pub timestamp: SystemTime,
    pub source_file: Option<PathBuf>,
    pub content: Option<Vec<u8>>,
}
