use std::path::Path;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use libbpf_rs::{Link, MapCore, ObjectBuilder, PerfBufferBuilder};

use crate::models::{EventType, MemoryEvent};

pub struct BpfTracer {
    obj: Option<libbpf_rs::Object>,
    perf_buffer: Option<libbpf_rs::PerfBuffer<'static>>,
    links: Vec<libbpf_rs::Link>,
    event_tx: Sender<MemoryEvent>,
    target_pid: i32,
    running: bool,
}

impl BpfTracer {
    pub fn new(event_tx: Sender<MemoryEvent>, target_pid: i32) -> Result<Self> {
        println!("[PID] {}", target_pid);

        Ok(Self {
            obj: None,
            perf_buffer: None,
            links: Vec::new(),
            event_tx,
            target_pid,
            running: false,
        })
    }

    pub fn start(&mut self) -> Result<()> {
        let bpf_file = "src/bpf/memory_tracer.bpf.o";

        if !Path::new(bpf_file).exists() {
            return Err(anyhow::anyhow!("BPF program file not found: {}", bpf_file));
        }

        // load
        let mut obj = match ObjectBuilder::default().open_file(bpf_file) {
            Ok(builder) => match builder.load() {
                Ok(obj) => obj,
                Err(e) => {
                    eprintln!("Failed to load BPF object: {}", e);
                    return Err(anyhow::anyhow!("Failed to load BPF object: {}", e));
                }
            },
            Err(e) => {
                eprintln!("Failed to open BPF file: {}", e);
                return Err(anyhow::anyhow!("Failed to open BPF file: {}", e));
            }
        };

        // attach
        for prog in obj.progs_mut() {
            let name = prog.name().to_str().unwrap_or_default();
            println!("Attaching program: {}", name);

            let _link = match name {
                "trace_mmap" => prog
                    .attach_tracepoint("syscalls", "sys_enter_mmap")
                    .map_err(|e| anyhow!("Failed to attach mmap: {}", e))?,
                "trace_munmap" => prog
                    .attach_tracepoint("syscalls", "sys_enter_munmap")
                    .map_err(|e| anyhow!("Failed to attach munmap: {}", e))?,
                "trace_mprotect" => prog
                    .attach_tracepoint("syscalls", "sys_enter_mprotect")
                    .map_err(|e| anyhow!("Failed to attach mprotect: {}", e))?,
                _ => continue,
            };

            self.links.push(_link);
        }

        let event_tx = Arc::new(Mutex::new(self.event_tx.clone()));
        let target_pid = self.target_pid;

        let mut events_map = None;
        for map in obj.maps_mut() {
            if map.name() == "events" {
                events_map = Some(map);
                break;
            }
        }

        let events = events_map.ok_or_else(|| anyhow::anyhow!("Failed to find events map"))?;

        let perf_buffer = PerfBufferBuilder::new(&events)
            .sample_cb(move |cpu, data: &[u8]| {
                if data.len() >= std::mem::size_of::<RawMemoryEvent>() {
                    // println!("Received data from CPU {}, size: {} bytes", cpu, data.len());

                    // parse event
                    let raw_event =
                        unsafe { std::ptr::read_unaligned(data.as_ptr() as *const RawMemoryEvent) };

                    // filter pid
                    if raw_event.pid as i32 == target_pid {
                        let event = MemoryEvent::from(raw_event);

                        if let Ok(tx) = event_tx.lock() {
                            let _ = tx.send(event);
                        }
                    }
                }
            })
            .lost_cb(|cpu, count| {
                eprintln!("Lost {} events on CPU {}", count, cpu);
            })
            .build()?;

        self.obj = Some(obj);
        self.perf_buffer = Some(perf_buffer);
        self.running = true;
        Ok(())
    }

    pub fn poll(&mut self, timeout_ms: i32) -> Result<()> {
        if !self.running {
            return Ok(());
        }

        if let Some(perf_buffer) = &mut self.perf_buffer {
            match perf_buffer.poll(Duration::from_millis(timeout_ms as u64)) {
                Ok(_) => {
                    // println!("Poll succseeful");
                }
                Err(e) => {
                    eprintln!("Poll error: {:?}", e);
                    return Err(anyhow::anyhow!("Failed to poll: {}", e));
                }
            }
        } else {
            return Err(anyhow::anyhow!("BPF tracer not properly initialized"));
        }

        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        println!("Stopping BPF tracer");
        self.running = false;
        self.perf_buffer = None;
        self.obj = None;
        Ok(())
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct RawMemoryEvent {
    addr: u64,
    length: u64,
    pid: u32,
    event_type: u32,
    timestamp: u64,
}

impl From<RawMemoryEvent> for MemoryEvent {
    fn from(raw: RawMemoryEvent) -> Self {
        let event_type = match raw.event_type {
            0 => EventType::Map,
            1 => EventType::Unmap,
            2 => EventType::ProtectionChange,
            _ => EventType::Map,
        };

        MemoryEvent {
            event_type,
            address: raw.addr as usize,
            size: raw.length as usize,
            timestamp: UNIX_EPOCH + Duration::from_nanos(raw.timestamp),
            pid: raw.pid as i32,
        }
    }
}
