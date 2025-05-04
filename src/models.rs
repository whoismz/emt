use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct ExecutablePage {
    pub address: usize,
    pub size: usize,
    pub timestamp: SystemTime,
    pub source_file: Option<PathBuf>,
    pub content: Option<Vec<u8>>,
    pub protection_flags: u32,
}

#[derive(Debug)]
pub struct MemoryEvent {
    pub event_type: EventType,
    pub address: usize,
    pub size: usize,
    pub timestamp: SystemTime,
    pub pid: i32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EventType {
    Map,
    Unmap,
    Mprotection,
}
