use emt::Tracer;
use std::thread;
use std::time::Duration;

mod common;
use common::do_memory_operations;

#[test]
fn test_trace_self_memory_operations() {
    // Get current process PID
    let self_pid = std::process::id() as i32;
    println!("Starting self-trace for PID: {}", self_pid);

    let mut tracer = Tracer::new(self_pid);
    if tracer.start().is_err() {
        println!("Failed to start self-tracer");
        return;
    }

    thread::sleep(Duration::from_millis(50));

    do_memory_operations();

    thread::sleep(Duration::from_millis(50));

    let pages = tracer.stop().unwrap();

    assert_eq!(pages.len(), 5);
    assert_eq!(&pages[2].content.as_ref().unwrap()[0..5], [0x90, 0x90, 0x90, 0x90, 0x90]);
    assert_eq!(&pages[3].content.as_ref().unwrap()[0..5], [0x91, 0x91, 0x91, 0x91, 0x91]);
}
