use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use nix::time::{ClockId, clock_gettime};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::bpf_runtime::BpfRuntime;
use crate::memory_analyzer::MemoryAnalyzer;
use crate::models::{EventType, ExecutablePage, MemoryEvent};

pub struct MemoryTracer {
    target_pid: i32,
    output_dir: PathBuf,
    save_content: bool,
    running: bool,
    event_tx: Option<Sender<MemoryEvent>>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl MemoryTracer {
    pub fn new(target_pid: i32, output_dir: impl AsRef<Path>, save_content: bool) -> Self {
        let output_dir = output_dir.as_ref().to_path_buf();

        std::fs::create_dir_all(&output_dir).expect("Failed to create output directory");

        Self {
            target_pid,
            output_dir,
            save_content,
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

        // Initialize tracer thread
        let output_dir = self.output_dir.clone();
        let target_pid = self.target_pid;
        let save_content = self.save_content;

        let thread_handle = thread::spawn(move || {
            if let Err(e) = Self::run(target_pid, event_tx, event_rx, output_dir, save_content) {
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

    fn print_memory_content(content: &[u8], address: usize) {
        println!("Memory content at 0x{:x}:", address);

        const BYTES_PER_ROW: usize = 16;
        for (i, chunk) in content.chunks(BYTES_PER_ROW).enumerate() {
            print!("0x{:08x}: ", address + i * BYTES_PER_ROW);

            for (j, byte) in chunk.iter().enumerate() {
                print!("{:02x} ", byte);
                if j == 7 {
                    print!(" ");
                }
            }

            if chunk.len() < BYTES_PER_ROW {
                let spaces =
                    (BYTES_PER_ROW - chunk.len()) * 3 + if chunk.len() <= 8 { 1 } else { 0 };
                for _ in 0..spaces {
                    print!(" ");
                }
            }

            print!(" | ");
            for &byte in chunk {
                if byte >= 32 && byte <= 126 {
                    print!("{}", byte as char);
                } else {
                    print!(".");
                }
            }
            println!();

            if i >= 15 {
                println!("... (showing only first 16 lines)");
                break;
            }
        }
        println!();
    }

    fn run(
        target_pid: i32,
        event_tx: Sender<MemoryEvent>,
        event_rx: Receiver<MemoryEvent>,
        output_dir: PathBuf,
        save_content: bool,
    ) -> Result<()> {
        let mut bpf_runtime = BpfRuntime::new(event_tx.clone(), target_pid)?;
        let memory_analyzer = MemoryAnalyzer::new(target_pid);

        // record currently known executable memory pages
        let mut known_pages: HashMap<usize, ExecutablePage> = HashMap::new();

        // log
        let log_path = output_dir.join(format!("memory_trace_{}.log", target_pid));
        let mut log_file = File::create(&log_path).context("Failed to create log file")?;

        writeln!(
            log_file,
            "ID, BPFTimestamp, DaemonTimestamp, EventType, Address, Size, File"
        )
        .context("Failed to write log header")?;

        println!(
            "Analyzing initial executable memory pages for PID: {}",
            target_pid
        );

        // get all current executable pages
        match memory_analyzer.get_executable_pages() {
            Ok(initial_pages) => {
                println!("Found {} initial executable pages", initial_pages.len());

                for mut page in initial_pages {
                    if save_content {
                        if let Err(e) = memory_analyzer.read_memory_page(&mut page) {
                            eprintln!(
                                "Failed to read initial memory page at {:x}: {:?}",
                                page.address, e
                            );
                        } else if let Some(content) = &page.content {
                            let content_path = output_dir
                                .join(format!("mem_{}_{:x}.bin", target_pid, page.address));
                            if let Err(e) = std::fs::write(&content_path, content) {
                                eprintln!("Failed to write memory content: {:?}", e);
                            }

                            Self::print_memory_content(content, page.address);
                        }
                    }

                    let source_file = page
                        .source_file
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| "Unknown".to_string());

                    println!(
                        "Logging page: addr={:x}, size={}, source={}",
                        page.address, page.size, source_file
                    );

                    writeln!(
                        log_file,
                        "{}, {}, {}, Initial, {:x}, {}, {}",
                        "-", "-", "-", page.address, page.size, source_file
                    )?;

                    known_pages.insert(page.address, page);
                }
            }
            Err(e) => {
                eprintln!("Error getting initial executable pages: {:?}", e);
            }
        }

        log_file.flush()?;

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
                    "Received memory event (ID: {}): type={:?}, addr={:x}, size={}",
                    event_id, event.event_type, event.address, event.size
                );
                
                match event.event_type {
                    EventType::Map | EventType::Mprotection => {
                        if let Ok(pages) = memory_analyzer.get_executable_pages() {
                            for mut page in pages {
                                let page_end = page.address + page.size;
                                let event_end = event.address + event.size;

                                if page.address < event_end && page_end > event.address {
                                    let is_new_page = !known_pages.contains_key(&page.address);
                                    let is_modified = !is_new_page
                                        && known_pages[&page.address].protection_flags
                                            != page.protection_flags;

                                    if is_new_page {
                                        println!("new page prot: {}", page.protection_flags);
                                    } else {
                                        println!(
                                            "old prot: {}, new prot: {}",
                                            known_pages[&page.address].protection_flags,
                                            page.protection_flags
                                        );
                                    }

                                    if is_new_page || is_modified {
                                        println!(
                                            "{} executable page detected: addr={:x}, size={}",
                                            if is_new_page { "New" } else { "Modified" },
                                            page.address,
                                            page.size
                                        );

                                        if save_content {
                                            if let Err(e) =
                                                memory_analyzer.read_memory_page(&mut page)
                                            {
                                                eprintln!("Failed to read memory: {:?}", e);
                                            } else if let Some(content) = &page.content {
                                                let timestamp = SystemTime::now()
                                                    .duration_since(UNIX_EPOCH)
                                                    .unwrap_or_default()
                                                    .as_secs();

                                                let content_path = output_dir.join(format!(
                                                    "mem_{}_{:x}_{}.bin",
                                                    target_pid, page.address, timestamp
                                                ));

                                                if let Err(e) =
                                                    std::fs::write(&content_path, content)
                                                {
                                                    eprintln!(
                                                        "Failed to write memory content: {:?}",
                                                        e
                                                    );
                                                }

                                                Self::print_memory_content(content, page.address);
                                            }
                                        }

                                        let ebpf_timestamp = event
                                            .timestamp
                                            .duration_since(UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_nanos();

                                        let daemon_timestamp = Duration::from(clock_gettime(
                                            ClockId::CLOCK_MONOTONIC,
                                        )?)
                                        .as_nanos();

                                        let source_file = page
                                            .source_file
                                            .as_ref()
                                            .map(|p| p.to_string_lossy().to_string())
                                            .unwrap_or_else(|| "Unknown".to_string());

                                        let event_type = match event.event_type {
                                            EventType::Map => "Map",
                                            EventType::Mprotection => "Mprotection",
                                            _ => unreachable!(),
                                        };

                                        writeln!(
                                            log_file,
                                            "{}, {}, {}, {}, {:x}, {}, {}",
                                            event_id,
                                            ebpf_timestamp,
                                            daemon_timestamp,
                                            event_type,
                                            page.address,
                                            page.size,
                                            source_file
                                        )?;

                                        log_file.flush()?;

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

                                let ebpf_timestamp = event
                                    .timestamp
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_nanos();

                                let daemon_timestamp =
                                    Duration::from(clock_gettime(ClockId::CLOCK_MONOTONIC)?)
                                        .as_nanos();

                                let source_file = page
                                    .source_file
                                    .as_ref()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_else(|| "Unknown".to_string());

                                if let Err(e) = writeln!(
                                    log_file,
                                    "{}, {}, {}, Unmap, {:x}, {}, {}",
                                    event_id,
                                    ebpf_timestamp,
                                    daemon_timestamp,
                                    addr,
                                    page.size,
                                    source_file
                                ) {
                                    eprintln!("Failed to write unmap log: {}", e);
                                }

                                if let Err(e) = log_file.flush() {
                                    eprintln!("Failed to flush log file: {}", e);
                                }
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
}

impl Drop for MemoryTracer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
