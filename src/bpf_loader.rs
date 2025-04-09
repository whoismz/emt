use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::sync::{Arc, Mutex};
use std::path::Path;

use anyhow::Result;
use libbpf_rs::{MapFlags, ObjectBuilder, PerfBufferBuilder, MapCore};

use crate::models::{EventType, MemoryEvent};

pub struct BpfTracer {
    obj: Option<libbpf_rs::Object>,
	perf_buffer: Option<libbpf_rs::PerfBuffer<'static>>,
    event_tx: Sender<MemoryEvent>,
    target_pid: i32,
    running: bool,
}

impl BpfTracer {
    pub fn new(event_tx: Sender<MemoryEvent>, target_pid: i32) -> Result<Self> {
        println!("Creating BPF tracer for PID: {}", target_pid);

        Ok(Self {
            obj: None,
			perf_buffer: None,
            event_tx,
            target_pid,
            running: false,
        })
    }

    pub fn start(&mut self) -> Result<()> {
        println!("Starting BPF tracer");

        let bpf_file = "src/bpf/memory_tracer.bpf.o";

		if !Path::new(bpf_file).exists() {
            return Err(anyhow::anyhow!("BPF program file not found: {}", bpf_file));
        }

		// 加载 BPF 对象
        let mut obj = ObjectBuilder::default()
            .open_file(bpf_file)?
            .load()?;

        // 获取需要的程序
        for prog in obj.progs_mut() {
            println!("Attaching program: {:?}", prog.name());
            let _ = prog.attach()?;
        }

        // 创建包装的 event_tx 以便在回调中使用
        let event_tx = Arc::new(Mutex::new(self.event_tx.clone()));
        let target_pid = self.target_pid;

		// 查找 events map
        let mut events_map = None;
        for map in obj.maps_mut() {
            if map.name() == "events" {
                events_map = Some(map);
                break;
            }
        }
        
        let events = events_map.ok_or_else(|| anyhow::anyhow!("Failed to find events map"))?;

        let perf_buffer = PerfBufferBuilder::new(&events)
            .sample_cb(move |_cpu, data: &[u8]| {
                if data.len() >= std::mem::size_of::<RawMemoryEvent>() {
                    // 解析原始事件
                    let raw_event = unsafe { *(data.as_ptr() as *const RawMemoryEvent) };

                    // 过滤掉不是目标进程的事件
                    if raw_event.pid as i32 == target_pid {
                        // 转换为 MemoryEvent
                        let event = MemoryEvent::from(raw_event);

                        // 发送事件
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

		// 轮询 perf 缓冲区获取事件
        if let Some(perf_buffer) = &mut self.perf_buffer {
            perf_buffer.poll(Duration::from_millis(timeout_ms as u64))?;
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
