// examples/check_bpf_compile.rs
use std::path::Path;

fn main() {
    // Check if BPF object exists
    let bpf_obj_path = "src/bpf/memory_tracer.bpf.o";

    match Path::new(bpf_obj_path).exists() {
        true => println!("BPF program compiled successfully: {}", bpf_obj_path),
        false => println!("BPF program doesn't exist at: {}", bpf_obj_path),
    }

    // Print some info about expected build process
    println!("\nBuild info:");
    println!("1. The build.rs script should compile the BPF C program");
    println!("2. The output should be at: {}", bpf_obj_path);
    println!("3. If you don't see the file, check that clang is installed");
    println!("   and configured properly for BPF compilation");
}
