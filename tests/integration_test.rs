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

    assert_eq!(pages.len(), 2);

    // TOBE TESTED
    // let expected = Some(vec![0x90; 5]);
    // assert_eq!(pages[1].content, expected);
}
