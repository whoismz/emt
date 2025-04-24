use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::bpf_loader::BpfTracer;
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

        // Create output directory
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
            if let Err(e) =
                Self::run_tracer(target_pid, event_tx, event_rx, output_dir, save_content)
            {
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
                event_type: EventType::Unmap, // use this as a stop signal
                address: 0,
                size: 0,
                timestamp: SystemTime::now(),
                pid: -1, // mark with -1 to indicate stop signal
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

    fn run_tracer(
        target_pid: i32,
        event_tx: Sender<MemoryEvent>,
        event_rx: Receiver<MemoryEvent>,
        output_dir: PathBuf,
        save_content: bool,
    ) -> Result<()> {
        let mut bpf_tracer = BpfTracer::new(event_tx.clone(), target_pid)?;
        let memory_analyzer = MemoryAnalyzer::new(target_pid);

        // record currently known executable memory pages
        let mut known_pages: HashMap<usize, ExecutablePage> = HashMap::new();

        // log
        let log_path = output_dir.join(format!("memory_trace_{}.log", target_pid));
        let mut log_file = File::create(&log_path).context("Failed to create log file")?;

        writeln!(log_file, "Time,EventType,Address,Size,SourceFile")
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
                        }
                    }

                    // log
                    let timestamp = page
                        .timestamp
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

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
                        "{},Initial,{:x},{},{}",
                        timestamp, page.address, page.size, source_file
                    )?;

                    known_pages.insert(page.address, page);
                }
            }
            Err(e) => {
                eprintln!("Error getting initial executable pages: {:?}", e);
            }
        }

        log_file.flush()?;

        bpf_tracer.start()?;

        // main loop for events from BPF
        let mut running = true;
        while running {
            // poll BPF events
            if let Err(e) = bpf_tracer.poll(100 /* ms */) {
                eprintln!("Error polling BPF events: {:?}", e);
            }

            // check for received memory events
            while let Ok(event) = event_rx.try_recv() {
                println!("event pid: {}\ntarget pid: {}", event.pid, target_pid);

                if event.pid == -1 {
                    running = false;
                    break;
                }

                if event.pid != target_pid {
                    continue;
                }

                println!(
                    "Received memory event: type={:?}, addr={:x}, size={}",
                    event.event_type, event.address, event.size
                );

                match event.event_type {
                    EventType::Map | EventType::ProtectionChange => {
                        // new executable memory or permission change
                        if let Ok(pages) = memory_analyzer.get_executable_pages() {
                            for mut page in pages {
                                if page.address <= event.address
                                    && page.address + page.size >= event.address + event.size
                                {
                                    if !known_pages.contains_key(&page.address)
                                        || known_pages[&page.address].protection_flags
                                            != page.protection_flags
                                    {
                                        println!(
                                            "New or modified executable page detected: addr={:x}, size={}",
                                            page.address, page.size
                                        );

                                        if save_content {
                                            if let Err(e) =
                                                memory_analyzer.read_memory_page(&mut page)
                                            {
                                                eprintln!("Failed to read memory: {:?}", e);
                                            } else if let Some(content) = &page.content {
                                                let content_path = output_dir.join(format!(
                                                    "mem_{}_{:x}_{}.bin",
                                                    target_pid,
                                                    page.address,
                                                    SystemTime::now()
                                                        .duration_since(UNIX_EPOCH)
                                                        .unwrap_or_default()
                                                        .as_secs()
                                                ));
                                                if let Err(e) =
                                                    std::fs::write(&content_path, content)
                                                {
                                                    eprintln!(
                                                        "Failed to write memory content: {:?}",
                                                        e
                                                    );
                                                }
                                            }
                                        }

                                        // log
                                        let timestamp = event
                                            .timestamp
                                            .duration_since(UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();

                                        let source_file = page
                                            .source_file
                                            .as_ref()
                                            .map(|p| p.to_string_lossy().to_string())
                                            .unwrap_or_else(|| "Unknown".to_string());

                                        let event_type = match event.event_type {
                                            EventType::Map => "Map",
                                            EventType::ProtectionChange => "ProtectionChange",
                                            _ => unreachable!(),
                                        };

                                        writeln!(
                                            log_file,
                                            "{},{},{:x},{},{}",
                                            timestamp,
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

                        for (addr, page) in &known_pages {
                            if *addr >= event.address
                                && *addr + page.size <= event.address + event.size
                            {
                                to_remove.push(*addr);

                                println!(
                                    "Unmapped executable page detected: addr={:x}, size={}",
                                    addr, page.size
                                );

                                // log
                                let timestamp = event
                                    .timestamp
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();

                                let source_file = page
                                    .source_file
                                    .as_ref()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_else(|| "Unknown".to_string());

                                writeln!(
                                    log_file,
                                    "{},Unmap,{:x},{},{}",
                                    timestamp, addr, page.size, source_file
                                )?;

                                log_file.flush()?;
                            }
                        }

                        for addr in to_remove {
                            known_pages.remove(&addr);
                        }
                    }
                }
            }
        }

        // stop BPF tracer
        bpf_tracer.stop()?;

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
