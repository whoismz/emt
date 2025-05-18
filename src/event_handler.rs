use log::debug;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::memory_analyzer::MemoryAnalyzer;
use crate::models::{Event, EventType, Page};
use crate::utils;

const PAGE_SIZE: usize = 4096;
const PAGE_MASK: usize = PAGE_SIZE - 1;

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

    fn get_pages_from_event(event: Event) -> Vec<Page> {
        let event_addr = event.addr;
        let event_size = event.size;
        let event_timestamp = event.timestamp;

        if event_size == 0 {
            return vec![];
        }

        let event_end = event_addr + event_size;

        let first_page_addr = event_addr & !PAGE_MASK;

        let last_page_addr = (event_end - 1) & !PAGE_MASK;

        let mut pages = Vec::new();
        let mut current_page_addr = first_page_addr;

        while current_page_addr <= last_page_addr {
            pages.push(Page {
                addr: current_page_addr,
                size: PAGE_SIZE,
                timestamp:event_timestamp,
                source_file: None,
                content: None,
            });
            current_page_addr += PAGE_SIZE;
        }

        pages
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
            EventType::Map => {
                let event_pages = EventHandler::get_pages_from_event(event);
                for page in event_pages {
                    self.known_pages.insert(page.addr, page);
                }
            }

            EventType::Mprotect => {
                let event_pages = EventHandler::get_pages_from_event(event);
                for page in event_pages {
                    self.known_pages.insert(page.addr, page);
                }
            }

            EventType::Unmap => {
                let event_pages = EventHandler::get_pages_from_event(event);

                for page in event_pages {
                    self.known_pages.remove(&page.addr);
                }
            }
        }
        true
    }
}
