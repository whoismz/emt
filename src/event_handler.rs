use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use log::debug;

use crate::models::{Event, EventType, Page};
use crate::utils;

const PAGE_SIZE: usize = 4096;
const PAGE_MASK: usize = PAGE_SIZE - 1;

pub struct EventHandler {
    target_pid: i32,
    event_counter: AtomicUsize,
    known_pages: HashMap<usize, Page>,
}

impl EventHandler {
    pub fn new(target_pid: i32) -> Self {
        Self {
            target_pid,
            event_counter: AtomicUsize::new(1),
            known_pages: HashMap::new(),
        }
    }

    fn extract_page_content(event_content: &[u8], page_offset: usize) -> Option<Vec<u8>> {
        if page_offset >= event_content.len() {
            return None;
        }

        // 创建页面内容，如果事件内容不足一个完整页面，其余部分保持为0
        let mut page_content = vec![0u8; PAGE_SIZE];

        // 复制事件内容到页面
        page_content[0..PAGE_SIZE]
            .copy_from_slice(&event_content[page_offset..page_offset + PAGE_SIZE]);

        Some(page_content)
    }

    fn get_pages_from_event(event: Event) -> Vec<Page> {
        let event_addr = event.addr;
        let event_size = event.size;
        let event_timestamp = event.timestamp_str;
        let event_content = event.content;

        if event_size == 0 {
            return vec![];
        }

        let event_end = event_addr + event_size;
        let first_page_addr = event_addr & !PAGE_MASK;
        let last_page_addr = (event_end - 1) & !PAGE_MASK;

        let mut pages = Vec::new();
        let mut current_page_addr = first_page_addr;

        while current_page_addr <= last_page_addr {
            // 计算当前页面在事件内容中的偏移
            let page_offset_in_event = current_page_addr - event_addr;

            // 提取当前页面的内容
            let page_content = if let Some(ref content) = event_content {
                Self::extract_page_content(content, page_offset_in_event)
            } else {
                None
            };

            pages.push(Page {
                addr: current_page_addr,
                size: PAGE_SIZE,
                timestamp: event_timestamp.clone(),
                source_file: None,
                content: page_content,
            });
            current_page_addr += PAGE_SIZE;
        }

        pages
    }

    pub fn get_all_pages(&self) -> Vec<Page> {
        let mut pages: Vec<Page> = self.known_pages.values().cloned().collect();
        pages.sort_by_key(|page| page.addr);
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
            "{}: type: {:?}, addr: {:x}, size: {}, timestamp: {:?}",
            event_id, event.event_type, event.addr, event.size, event.timestamp_str,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Event, EventType};
    use std::time::SystemTime;

    fn create_test_event(event_type: EventType, addr: usize, size: usize, pid: i32) -> Event {
        Event {
            event_type,
            addr,
            size,
            timestamp: SystemTime::now(),
            timestamp_str: String::new(),
            pid,
            content: None,
        }
    }

    #[test]
    fn test_event_handler_creation() {
        let handler = EventHandler::new(1);
        assert_eq!(handler.target_pid, 1);
        assert_eq!(handler.known_pages.len(), 0);
        assert_eq!(handler.event_counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_get_pages_from_event_single_page() {
        let event = create_test_event(EventType::Map, 0x1100, 100, 1);
        let pages = EventHandler::get_pages_from_event(event);

        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].addr, 0x1000);
        assert_eq!(pages[0].size, PAGE_SIZE);
    }

    #[test]
    fn test_get_pages_from_event_multiple_pages() {
        let event = create_test_event(EventType::Map, 0x1F00, 0x400, 1);
        let pages = EventHandler::get_pages_from_event(event);

        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].addr, 0x1000);
        assert_eq!(pages[1].addr, 0x2000);
    }

    #[test]
    fn test_get_pages_from_event_page_aligned() {
        let event = create_test_event(EventType::Map, 0x2000, 0x1000, 1);
        let pages = EventHandler::get_pages_from_event(event);

        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].addr, 0x2000);
    }

    #[test]
    fn test_get_pages_from_event_zero_size() {
        let event = create_test_event(EventType::Map, 0x1000, 0, 1);
        let pages = EventHandler::get_pages_from_event(event);

        assert_eq!(pages.len(), 0);
    }

    #[test]
    fn test_get_pages_from_event_large_span() {
        let event = create_test_event(EventType::Map, 0x1800, 0x3000, 1);
        let pages = EventHandler::get_pages_from_event(event);

        assert_eq!(pages.len(), 4);
        assert_eq!(pages[0].addr, 0x1000);
        assert_eq!(pages[1].addr, 0x2000);
        assert_eq!(pages[2].addr, 0x3000);
        assert_eq!(pages[3].addr, 0x4000);
    }

    #[test]
    fn test_process_wrong_pid() {
        let mut handler = EventHandler::new(1);
        let event = create_test_event(EventType::Map, 0x1000, 0x1000, 2);

        let result = handler.process(event);
        assert!(result);
        assert_eq!(handler.known_pages.len(), 0);
    }

    #[test]
    fn test_process_shutdown_event() {
        let mut handler = EventHandler::new(1);
        let event = Event {
            event_type: EventType::Map,
            addr: 0x1000,
            size: 0x1000,
            timestamp: SystemTime::now(),
            timestamp_str: String::new(),
            pid: -1,
            content: None,
        };

        let result = handler.process(event);
        assert!(!result);
    }

    #[test]
    fn test_process_map_event() {
        let mut handler = EventHandler::new(1);
        let event = create_test_event(EventType::Map, 0x1000, 0x1000, 1);

        let result = handler.process(event);
        assert!(result);
        assert_eq!(handler.known_pages.len(), 1);
        assert!(handler.known_pages.contains_key(&0x1000));
    }

    #[test]
    fn test_process_map_event_multiple_pages() {
        let mut handler = EventHandler::new(1);
        let event = create_test_event(EventType::Map, 0x1000, 0x3000, 1);

        let result = handler.process(event);
        assert!(result);
        assert_eq!(handler.known_pages.len(), 3);
        assert!(handler.known_pages.contains_key(&0x1000));
        assert!(handler.known_pages.contains_key(&0x2000));
        assert!(handler.known_pages.contains_key(&0x3000));
    }

    #[test]
    fn test_process_mprotect_event() {
        let mut handler = EventHandler::new(1);
        let event = create_test_event(EventType::Mprotect, 0x2000, 0x1000, 1);

        let result = handler.process(event);
        assert!(result);
        assert_eq!(handler.known_pages.len(), 1);
        assert!(handler.known_pages.contains_key(&0x2000));
    }

    #[test]
    fn test_process_unmap_event() {
        let mut handler = EventHandler::new(1);

        let map_event = create_test_event(EventType::Map, 0x1000, 0x2000, 1);
        handler.process(map_event);
        assert_eq!(handler.known_pages.len(), 2);

        let unmap_event = create_test_event(EventType::Unmap, 0x1000, 0x1000, 1);
        let result = handler.process(unmap_event);
        assert!(result);
        assert_eq!(handler.known_pages.len(), 1);
        assert!(!handler.known_pages.contains_key(&0x1000));
        assert!(handler.known_pages.contains_key(&0x2000));
    }

    #[test]
    fn test_process_unmap_partial_overlap() {
        let mut handler = EventHandler::new(1);

        let map_event = create_test_event(EventType::Map, 0x1000, 0x4000, 1);
        handler.process(map_event);
        assert_eq!(handler.known_pages.len(), 4);

        let unmap_event = create_test_event(EventType::Unmap, 0x2000, 0x2000, 1);
        handler.process(unmap_event);
        assert_eq!(handler.known_pages.len(), 2);
        assert!(handler.known_pages.contains_key(&0x1000));
        assert!(!handler.known_pages.contains_key(&0x2000));
        assert!(!handler.known_pages.contains_key(&0x3000));
        assert!(handler.known_pages.contains_key(&0x4000));
    }

    #[test]
    fn test_process_overlapping_events() {
        let mut handler = EventHandler::new(1);

        let event1 = create_test_event(EventType::Map, 0x1000, 0x1000, 1);
        handler.process(event1);

        let event2 = create_test_event(EventType::Map, 0x1800, 0x1000, 1);
        handler.process(event2);

        assert_eq!(handler.known_pages.len(), 2);
        assert!(handler.known_pages.contains_key(&0x1000));
        assert!(handler.known_pages.contains_key(&0x2000));
    }

    #[test]
    fn test_event_counter_increment() {
        let mut handler = EventHandler::new(1);
        let initial_counter = handler.event_counter.load(Ordering::SeqCst);

        let event1 = create_test_event(EventType::Map, 0x1000, 0x1000, 1);
        handler.process(event1);
        assert_eq!(
            handler.event_counter.load(Ordering::SeqCst),
            initial_counter + 1
        );

        let event2 = create_test_event(EventType::Mprotect, 0x2000, 0x1000, 1);
        handler.process(event2);
        assert_eq!(
            handler.event_counter.load(Ordering::SeqCst),
            initial_counter + 2
        );
    }
}
