use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::bpf_runtime::BpfRuntime;
use crate::memory_analyzer::MemoryAnalyzer;
use crate::models::{EventType, ExecutablePage, MemoryEvent};

pub struct MemoryTracer {
    target_pid: i32,
    running: bool,
    event_tx: Option<Sender<MemoryEvent>>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl MemoryTracer {
    pub fn new(target_pid: i32) -> Self {
        Self {
            target_pid,
            running: false,
            event_tx: None,
            thread_handle: None,
        }
    }

    pub fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }

        let (event_tx, event_rx) = channel();
        self.event_tx = Some(event_tx.clone());

        let target_pid = self.target_pid;

        let thread_handle = thread::spawn(move || {
            if let Err(e) = Self::run(target_pid, event_tx, event_rx) {
                eprintln!("Tracer error: {:?}", e);
            }
        });

        self.thread_handle = Some(thread_handle);
        self.running = true;

        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }

        // notify tracer thread to stop
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(MemoryEvent {
                event_type: EventType::Unmap,
                address: 0,
                size: 0,
                timestamp: SystemTime::now(),
                pid: -1,
                content: None,
            });
        }

        // wait for thread to complete
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }

        self.running = false;
        self.event_tx = None;

        Ok(())
    }

    fn run(
        target_pid: i32,
        event_tx: Sender<MemoryEvent>,
        event_rx: Receiver<MemoryEvent>,
    ) -> Result<()> {
        let mut bpf_runtime = BpfRuntime::new(event_tx.clone(), target_pid)?;
        let memory_analyzer = MemoryAnalyzer::new(target_pid);

        // record currently known executable memory pages
        let mut known_pages: HashMap<usize, ExecutablePage> = HashMap::new();

        bpf_runtime.start("./src/bpf/memory_tracer_ringbuf.bpf.o")?;

        static EVENT_COUNTER: AtomicUsize = AtomicUsize::new(1);

        // main loop for events from BPF
        let mut running = true;
        while running {
            // poll BPF events
            if let Err(e) = bpf_runtime.poll(Duration::from_millis(100)) {
                eprintln!("Error polling BPF events: {:?}", e);
            }

            // check for received memory events
            while let Ok(event) = event_rx.try_recv() {
                if event.pid == -1 {
                    running = false;
                    break;
                }

                if event.pid != target_pid {
                    continue;
                }

                let event_id = EVENT_COUNTER.fetch_add(1, Ordering::SeqCst);

                println!(
                    "{}: type={:?}, addr={:x}, size={}",
                    event_id, event.event_type, event.address, event.size
                );

                if let Some(content) = &event.content {
                    println!("Event includes memory content of size: {} bytes", content.len());
                    Self::print_memory_content(content, event.address);
                }

                match event.event_type {
                    EventType::Map | EventType::Mprotection => {
                        if let Ok(pages) = memory_analyzer.get_executable_pages() {
                            for page in pages {
                                let page_end = page.address + page.size;
                                let event_end = event.address + event.size;

                                if page.address < event_end && page_end > event.address {
                                    let is_new_page = !known_pages.contains_key(&page.address);
                                    let is_modified = !is_new_page
                                        && known_pages[&page.address].protection_flags
                                            != page.protection_flags;

                                    if is_new_page || is_modified {
                                        /*
                                        println!(
                                            "{} executable page detected: addr={:x}, size={}",
                                            if is_new_page { "New" } else { "Modified" },
                                            page.address,
                                            page.size
                                        );
                                         */

                                        known_pages.insert(page.address, page);
                                    }
                                }
                            }
                        }
                    }
                    EventType::Unmap => {
                        let mut to_remove = Vec::new();
                        let unmap_start = event.address;
                        let unmap_end = event.address + event.size;

                        for (addr, page) in &known_pages {
                            let page_start = *addr;
                            let page_end = *addr + page.size;

                            if page_start < unmap_end && page_end > unmap_start {
                                to_remove.push(*addr);
                            }
                        }

                        for addr in to_remove {
                            known_pages.remove(&addr);
                        }
                    }
                }
            }
        }

        bpf_runtime.stop()?;

        println!(
            "Memory tracer stopped. Logged {} executable pages.",
            known_pages.len()
        );

        Ok(())
    }

    fn print_memory_content(content: &[u8], address: usize) {
        println!("Memory content at 0x{:x} ({} bytes):", address, content.len());

        const BYTES_PER_ROW: usize = 16;
        for (i, chunk) in content.chunks(BYTES_PER_ROW).enumerate() {
            let mut hex_line = format!("0x{:08x}: ", address + i * BYTES_PER_ROW);

            for (j, byte) in chunk.iter().enumerate() {
                hex_line.push_str(&format!("{:02x} ", byte));
                if j == 7 {
                    hex_line.push(' ');
                }
            }

            if chunk.len() < BYTES_PER_ROW {
                let spaces = (BYTES_PER_ROW - chunk.len()) * 3 + if chunk.len() <= 8 { 1 } else { 0 };
                for _ in 0..spaces {
                    hex_line.push(' ');
                }
            }

            hex_line.push_str(" | ");
            for &byte in chunk {
                if byte >= 32 && byte <= 126 {
                    hex_line.push(byte as char);
                } else {
                    hex_line.push('.');
                }
            }

            println!("{}", hex_line);

            if i >= 15 && content.len() > 16 * 16 {
                println!("... (showing only first 16 lines of {} total)",
                     (content.len() + BYTES_PER_ROW - 1) / BYTES_PER_ROW);
                break;
            }
        }
        println!("");
    }
}

impl Drop for MemoryTracer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
