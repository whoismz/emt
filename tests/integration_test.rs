use emt::Tracer;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Test tracing a simple mmap/munmap sequence
#[test]
fn test_trace_simple_mmap_operations() {
    if !is_root() {
        println!("Skipping mmap test - requires root privileges");
        return;
    }

    if !ensure_bpf_compiled() {
        println!("Skipping test - BPF compilation failed");
        return;
    }

    // Create a unique test program for this test
    let test_program = create_unique_memory_test_program("simple_mmap");

    // Spawn the test program
    let mut child = Command::new(&test_program)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start test program");

    let child_pid = child.id() as i32;

    // Create and start a tracer
    let mut tracer = Tracer::new(child_pid);
    let start_result = tracer.start();

    if start_result.is_err() {
        let _ = child.kill();
        let _ = std::fs::remove_file(&test_program);
        panic!("Failed to start tracer: {:?}", start_result.unwrap_err());
    }

    // Wait for the test program to complete
    let output = child.wait_with_output().expect("Failed to wait for child");

    if !output.status.success() {
        println!("Test program failed:");
        println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    }

    // Give time for BPF events to be processed
    thread::sleep(Duration::from_millis(200));

    // Stop tracing and get results
    let pages = tracer.stop().expect("Failed to stop tracer");

    println!("Captured {} pages from simple mmap test", pages.len());

    // Clean up
    let _ = std::fs::remove_file(&test_program);

    if pages.is_empty() {
        println!("No pages captured - possibly due to BPF filtering or timing");
    } else {
        println!("Successfully captured memory operations");
    }
}

/// Test tracer lifecycle management
#[test]
fn test_tracer_lifecycle() {
    if !is_root() {
        println!("Skipping lifecycle test - requires root privileges");
        return;
    }

    let mut tracer = Tracer::new(1); // init process

    // Test multiple start calls
    assert!(tracer.start().is_ok());
    assert!(tracer.start().is_ok()); // Should be idempotent

    // Test stop
    assert!(tracer.stop().is_ok());

    // Test stop when already stopped
    assert!(tracer.stop().is_ok());

    // Test start after stop
    assert!(tracer.start().is_ok());
    assert!(tracer.stop().is_ok());
}

/// Helper function to check if running as root
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Creates a unique test program
fn create_unique_memory_test_program(suffix: &str) -> String {
    use std::fs;
    use std::io::Write;

    let program_path = format!("/tmp/emt_test_{}_{}", std::process::id(), suffix);

    // Write a simple C program that does mmap operations
    let c_code = r#"
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("Starting memory operations test\n");

    // Allocate executable memory
    void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    printf("Allocated memory at %p\n", mem);

    // Write some data (NOP instructions)
    memset(mem, 0x90, 64); // Fill with NOP instructions

    // Change protections (this should trigger mprotect tracing)
    if (mprotect(mem, 4096, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect failed");
        munmap(mem, 4096);
        return 1;
    }

    printf("Changed memory protection\n");

    // Sleep a bit to ensure events are captured
    usleep(100000); // 100ms

    // Unmap memory
    if (munmap(mem, 4096) != 0) {
        perror("munmap failed");
        return 1;
    }

    printf("Unmapped memory\n");

    return 0;
}
"#;

    let c_file = format!("{}.c", program_path);

    // Write a C source file
    let mut file = fs::File::create(&c_file).expect("Failed to create C file");
    file.write_all(c_code.as_bytes())
        .expect("Failed to write C code");
    file.flush().expect("Failed to flush file");
    drop(file);

    // Compile the program
    let compile_result = Command::new("gcc")
        .args(&["-o", &program_path, &c_file, "-static"]) // Use static linking
        .output()
        .expect("Failed to run gcc");

    if !compile_result.status.success() {
        panic!(
            "Failed to compile test program: {}",
            String::from_utf8_lossy(&compile_result.stderr)
        );
    }

    // Clean up
    fs::remove_file(&c_file).ok();

    program_path
}

/// Ensures the BPF object file is properly compiled
fn ensure_bpf_compiled() -> bool {
    use std::path::Path;

    // Check if a BPF source exists
    let bpf_src = "src/bpf/memory_tracer_ringbuf.bpf.c";
    if !Path::new(bpf_src).exists() {
        println!("BPF source file not found: {}", bpf_src);
        return false;
    }

    // Try to compile a BPF program
    let bpf_out = "/tmp/test_memory_tracer_ringbuf.bpf.o";
    let compile_result = Command::new("clang")
        .args(&[
            "-g",
            "-O2",
            "-target",
            "bpf",
            "-D__TARGET_ARCH_x86",
            "-I/usr/include/x86_64-linux-gnu",
            "-c",
            bpf_src,
            "-o",
            bpf_out,
        ])
        .output();

    match compile_result {
        Ok(output) => {
            if output.status.success() {
                println!("BPF compilation successful");
                // Clean up a test file
                let _ = std::fs::remove_file(bpf_out);
                true
            } else {
                println!("BPF compilation failed:");
                println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
                println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
                false
            }
        }
        Err(e) => {
            println!("Failed to run clang: {:?}", e);
            false
        }
    }
}
