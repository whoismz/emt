use std::path::Path;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use libbpf_rs::{Link, MapCore, Object, ObjectBuilder, RingBuffer, RingBufferBuilder};

use crate::models::{EventType, MemoryEvent};

// Maximum size of the content snapshot in the BPF program
const MAX_SNAPSHOT_SIZE: usize = 256;

/// Manages the BPF program lifecycle including loading, attaching, and event processing
pub struct BpfRuntime {
    bpf_object: Option<Object>,
    ring_buffer: Option<RingBuffer<'static>>,
    probe_links: Vec<Link>,
    event_tx: Sender<MemoryEvent>,
    target_pid: i32,
    is_active: bool,
}

impl BpfRuntime {
    /// Creates a new BPF runtime instance
    ///
    /// # Arguments
    /// * `event_tx` - Channel sender for memory events
    /// * `target_pid` - PID of the process to monitor
    pub fn new(event_tx: Sender<MemoryEvent>, target_pid: i32) -> Result<Self> {
        Ok(Self {
            bpf_object: None,
            ring_buffer: None,
            probe_links: Vec::new(),
            event_tx,
            target_pid,
            is_active: false,
        })
    }

    pub fn start(&mut self, bpf_path: impl AsRef<Path>) -> Result<()> {
        if self.is_active {
            return Ok(());
        }

        let bpf_path = bpf_path.as_ref();
        if !bpf_path.exists() {
            return Err(anyhow!("BPF program not found at {}", bpf_path.display()));
        }

        // load bpf object
        let mut bpf_object = ObjectBuilder::default()
            .open_file(bpf_path)
            .context("Failed to open BPF object file")?
            .load()
            .context("Failed to load BPF object")?;

        // attach
        self.attach_probes(&mut bpf_object)?;

        self.init_ring_buffer(&bpf_object)?;

        self.bpf_object = Some(bpf_object);
        self.is_active = true;
        Ok(())
    }

    /// Attaches all BPF programs to their respective tracepoints
    fn attach_probes(&mut self, bpf_object: &mut Object) -> Result<()> {
        const TRACEPOINTS: &[(&str, &str, &str)] = &[
            ("trace_enter_mmap", "syscalls", "sys_enter_mmap"),
            ("trace_exit_mmap", "syscalls", "sys_exit_mmap"),
            ("trace_munmap", "syscalls", "sys_enter_munmap"),
            ("trace_enter_mprotect", "syscalls", "sys_enter_mprotect"),
            ("trace_exit_mprotect", "syscalls", "sys_exit_mprotect"),
        ];

        for prog in bpf_object.progs_mut() {
            let prog_name = prog.name().to_str().unwrap_or_default();

            if let Some((_, subsystem, tracepoint)) =
                TRACEPOINTS.iter().find(|(name, _, _)| *name == prog_name)
            {
                let link = prog
                    .attach_tracepoint(subsystem, tracepoint)
                    .with_context(|| format!("Failed to attach {prog_name}"))?;
                self.probe_links.push(link);
            }
        }
        Ok(())
    }

    fn init_ring_buffer(&mut self, bpf_object: &Object) -> Result<()> {
        let events_map = bpf_object
            .maps()
            .find(|map| map.name() == "events")
            .ok_or_else(|| anyhow!("Failed to find events map"))?;

        let event_tx = Arc::new(Mutex::new(self.event_tx.clone()));
        let target_pid = self.target_pid;

        let mut builder = RingBufferBuilder::new();

        builder
            .add(&events_map, move |data: &[u8]| {
                Self::handle_ringbuf_event(data, &event_tx, target_pid);
                0
            })
            .context("Failed to add callback to ring buffer")?;

        self.ring_buffer = Some(builder.build().context("Failed to create ring buffer")?);

        Ok(())
    }

    fn handle_ringbuf_event(
        data: &[u8],
        event_tx: &Arc<Mutex<Sender<MemoryEvent>>>,
        target_pid: i32,
    ) {
        use std::mem::size_of;

        if data.len() >= size_of::<RawMemoryEvent>() {
            let raw_event =
                unsafe { std::ptr::read_unaligned(data.as_ptr() as *const RawMemoryEvent) };

            if raw_event.pid as i32 == target_pid {
                let event = MemoryEvent::from(raw_event);

                if let Ok(tx) = event_tx.lock() {
                    let _ = tx.send(event);
                }
            }
        }
    }

    pub fn poll(&mut self, timeout: Duration) -> Result<()> {
        if !self.is_active {
            return Ok(());
        }

        self.ring_buffer
            .as_mut()
            .ok_or(anyhow!("Perf buffer not initialized"))?
            .poll(timeout)
            .context("Failed to poll events")
    }

    pub fn stop(&mut self) -> Result<()> {
        self.is_active = false;
        self.ring_buffer.take();
        self.bpf_object.take();
        self.probe_links.clear();
        Ok(())
    }
}

impl Drop for BpfRuntime {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
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
            2 => EventType::Mprotection,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn test_new_bpf_runtime() {
        let (tx, _rx) = mpsc::channel();
        let runtime = BpfRuntime::new(tx, 1234).unwrap();

        assert!(!runtime.is_active);
        assert_eq!(runtime.target_pid, 1234);
    }

    #[test]
    fn test_start_stop() {
        let (tx, _rx) = mpsc::channel();
        let mut runtime = BpfRuntime::new(tx, 1234).unwrap();

        assert!(runtime.start("nonexistent.bpf.o").is_err());

        runtime.is_active = true;
        runtime.stop().unwrap();
        assert!(!runtime.is_active);
    }

    #[test]
    fn test_raw_event_conversion() {
        let raw = RawMemoryEvent {
            addr: 0x1000,
            length: 4096,
            pid: 1234,
            event_type: 1,
            timestamp: 1_000_000_000, // 1 second in ns
        };

        let event: MemoryEvent = raw.into();

        assert_eq!(event.event_type, EventType::Unmap);
        assert_eq!(event.address, 0x1000);
        assert_eq!(event.size, 4096);
        assert_eq!(event.pid, 1234);
        assert_eq!(event.timestamp, UNIX_EPOCH + Duration::from_secs(1));
    }

    #[test]
    fn test_drop_impl() {
        let (tx, _rx) = mpsc::channel();
        let mut runtime = BpfRuntime::new(tx, 1234).unwrap();
        runtime.is_active = true;

        drop(runtime);
    }
}
