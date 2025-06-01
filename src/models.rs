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
            pid: -1,
            content: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Page {
    pub addr: usize,
    pub size: usize,
    pub timestamp: SystemTime,
    pub source_file: Option<PathBuf>,
    pub content: Option<Vec<u8>>,
}

impl Page {
    pub fn new(
        addr: usize,
        size: usize,
        timestamp: SystemTime,
        source_file: Option<PathBuf>,
    ) -> Self {
        Self {
            addr,
            size,
            timestamp,
            source_file,
            content: None,
        }
    }
}
