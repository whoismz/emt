use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use libbpf_rs::{ErrorKind, Link, MapCore, Object, ObjectBuilder, RingBuffer, RingBufferBuilder};

use crate::models::{Event, EventType};

const MAX_SNAPSHOT_SIZE: usize = 256;

/// Manages the BPF program lifecycle including loading, attaching, and event processing
pub struct BpfRuntime {
    bpf_object: Option<Object>,
    ring_buffer: Option<RingBuffer<'static>>,
    probe_links: Vec<Link>,
    event_tx: Sender<Event>,
    target_pid: i32,
    is_active: bool,
}

impl BpfRuntime {
    /// Creates a new BPF runtime instance
    ///
    /// # Arguments
    /// * `event_tx` - Channel sender for memory events
    /// * `target_pid` - PID of the process to monitor
    pub fn new(event_tx: Sender<Event>, target_pid: i32) -> Result<Self> {
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

        // Load BPF object
        let mut bpf_object = ObjectBuilder::default()
            .open_file(bpf_path)
            .context("Failed to open BPF object file")?
            .load()
            .context("Failed to load BPF object")?;

        // Attach probes and initialize the ring buffer
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

        let event_tx = Arc::new(self.event_tx.clone());
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

    fn handle_ringbuf_event(data: &[u8], event_tx: &Arc<Sender<Event>>, target_pid: i32) {
        use std::mem::size_of;

        if data.len() >= size_of::<RawMemoryEvent>() {
            let raw_event =
                unsafe { std::ptr::read_unaligned(data.as_ptr() as *const RawMemoryEvent) };

            if raw_event.pid as i32 == target_pid {
                let event = Event::from(raw_event);
                let _ = event_tx.send(event);
            }
        }
    }

    pub fn poll(&mut self, timeout: Duration) -> Result<()> {
        if !self.is_active {
            return Ok(());
        }

        let rb = self
            .ring_buffer
            .as_mut()
            .ok_or(anyhow!("Ring buffer not initialized"))?;

        loop {
            match rb.poll(timeout) {
                Ok(()) => break Ok(()),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => break Err(e).context("Failed to poll events"),
            }
        }
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
    content_size: u64,
    content: [u8; MAX_SNAPSHOT_SIZE],
}

impl From<RawMemoryEvent> for Event {
    fn from(raw: RawMemoryEvent) -> Self {
        let event_type = match raw.event_type {
            0 => EventType::Map,
            1 => EventType::Unmap,
            2 => EventType::Mprotect,
            _ => EventType::Map,
        };

        let content = if raw.content_size > 0 && raw.content_size <= MAX_SNAPSHOT_SIZE as u64 {
            let mut content_vec = Vec::with_capacity(raw.content_size as usize);
            content_vec.extend_from_slice(&raw.content[..raw.content_size as usize]);
            Some(content_vec)
        } else {
            None
        };

        Event {
            event_type,
            addr: raw.addr as usize,
            size: raw.length as usize,
            timestamp: UNIX_EPOCH + Duration::from_nanos(raw.timestamp),
            pid: raw.pid as i32,
            content,
        }
    }
}
