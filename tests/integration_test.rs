use emt::Tracer;
use std::thread;
use std::time::Duration;

mod common;
use common::do_memory_operations;

#[test]
fn test_tracer_lifecycle() {
    let mut tracer = Tracer::new(1);

    let start_result = tracer.start();
    assert!(start_result.is_ok());

    // Multiple starts. TO BE TESTED
    // assert!(tracer.start().is_err());

    let stop_result = tracer.stop();
    assert!(stop_result.is_ok());

    // Multiple stops. TO BE TESTED
    // assert!(tracer.stop().is_ok());
}

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

    unsafe {
        let bytes = std::slice::from_raw_parts(pages[2].addr as *const u8, 5);
        assert_eq!(bytes, [0x90, 0x90, 0x90, 0x90, 0x90]);
    }

    unsafe {
        let bytes = std::slice::from_raw_parts(pages[3].addr as *const u8, 5);
        assert_eq!(bytes, [0x91, 0x91, 0x91, 0x91, 0x91]);
    }
}
