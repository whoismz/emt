use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::{Duration, SystemTime};

use anyhow::Result;

use crate::analyzer::MemoryAnalyzer;
use crate::ebpf::BpfRuntime;
use crate::models::{Event, EventType, Page};

pub struct Handler {
    target_pid: i32,
    running: bool,
    event_tx: Option<Sender<Event>>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl Handler {
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
            let _ = tx.send(Event {
                event_type: EventType::Unmap,
                addr: 0,
                size: 0,
                flag: 0,
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

    fn run(target_pid: i32, event_tx: Sender<Event>, event_rx: Receiver<Event>) -> Result<()> {
        let mut bpf_runtime = BpfRuntime::new(event_tx.clone(), target_pid)?;
        let memory_analyzer = MemoryAnalyzer::new(target_pid);

        // record currently known executable memory pages
        let mut known_pages: HashMap<usize, Page> = HashMap::new();

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
                    event_id, event.event_type, event.addr, event.size
                );

                match event.event_type {
                    EventType::Map | EventType::Mprotect => {
                        if let Ok(pages) = memory_analyzer.get_executable_pages() {
                            for page in pages {
                                let page_end = page.addr + page.size;
                                let event_end = event.addr + event.size;

                                if page.addr < event_end && page_end > event.addr {
                                    let is_new_page = !known_pages.contains_key(&page.addr);
                                    let is_modified =
                                        !is_new_page && known_pages[&page.addr].flag != page.flag;

                                    if is_new_page || is_modified {
                                        /*
                                        println!(
                                            "{} executable page detected: addr={:x}, size={}",
                                            if is_new_page { "New" } else { "Modified" },
                                            page.address,
                                            page.size
                                        );
                                         */

                                        known_pages.insert(page.addr, page);
                                    }
                                }
                            }
                        }
                    }
                    EventType::Unmap => {
                        let mut to_remove = Vec::new();
                        let unmap_start = event.addr;
                        let unmap_end = event.addr + event.size;

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
                let spaces =
                    (BYTES_PER_ROW - chunk.len()) * 3 + if chunk.len() <= 8 { 1 } else { 0 };
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
                println!(
                    "... (showing only first 16 lines of {} total)",
                    (content.len() + BYTES_PER_ROW - 1) / BYTES_PER_ROW
                );
                break;
            }
        }
        println!();
    }
}

impl Drop for Handler {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
