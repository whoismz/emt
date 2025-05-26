use std::path::PathBuf;
use std::process::Command;

fn main() {
    let bpf_src = "src/bpf/memory_tracer_ringbuf.bpf.c";
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let bpf_out = out_dir.join("memory_tracer_ringbuf.bpf.o");

    println!("cargo:rerun-if-changed={}", bpf_src);

    // Use clang to compile a BPF program
    let status = Command::new("clang")
        .args(["-g", "-O2", "-target", "bpf", "-c", bpf_src, "-o"])
        .arg(&bpf_out)
        .status()
        .expect("Failed to execute clang");

    if !status.success() {
        panic!("Failed to compile BPF program");
    }
}
