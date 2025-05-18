use log::debug;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::memory_analyzer::MemoryAnalyzer;
use crate::models::{Event, EventType, Page};
use crate::utils;

pub struct EventHandler {
    target_pid: i32,
    event_counter: AtomicUsize,
    known_pages: HashMap<usize, Page>,
    memory_analyzer: MemoryAnalyzer,
}

impl EventHandler {
    pub fn new(target_pid: i32) -> Self {
        Self {
            target_pid,
            event_counter: AtomicUsize::new(1),
            known_pages: HashMap::new(),
            memory_analyzer: MemoryAnalyzer::new(target_pid),
        }
    }

    pub fn process(&mut self, event: Event) -> bool {
        if event.pid == -1 {
            return false;
        }

        if event.pid != self.target_pid {
            return true;
        }

        let event_id = self.event_counter.fetch_add(1, Ordering::SeqCst);
        debug!(
            "{}: type={:?}, addr={:x}, size={}",
            event_id, event.event_type, event.addr, event.size
        );

        if let Some(content) = &event.content {
            utils::print_memory_content(content, event.addr);
        }

        match event.event_type {
            EventType::Map | EventType::Mprotect => {
                if let Ok(pages) = self.memory_analyzer.get_executable_pages() {
                    for page in pages {
                        let page_end = page.addr + page.size;
                        let event_end = event.addr + event.size;

                        if page.addr < event_end && page_end > event.addr {
                            if !self.known_pages.contains_key(&page.addr) {
                                self.known_pages.insert(page.addr, page);
                            }
                        }
                    }
                }
            }
            EventType::Unmap => {
                let unmap_start = event.addr;
                let unmap_end = event.addr + event.size;
                let mut to_remove = vec![];

                for (&addr, page) in &self.known_pages {
                    let page_end = addr + page.size;
                    if addr < unmap_end && page_end > unmap_start {
                        to_remove.push(addr);
                    }
                }

                for addr in to_remove {
                    self.known_pages.remove(&addr);
                }
            }
        }
        true
    }
}
