use std::process::Command;

fn main() {
    let bpf_src = "src/bpf/memory_tracer.bpf.c";
    let bpf_out = "src/bpf/memory_tracer.bpf.o";

    println!("cargo:rerun-if-changed={}", bpf_src);

    // use clang to compile BPF program
    let status = Command::new("clang")
        .args(&["-g", "-O2", "-target", "bpf", "-c", bpf_src, "-o", bpf_out])
        .status()
        .expect("Failed to execute clang");

    if !status.success() {
        panic!("Failed to compile BPF program");
    }

    println!("cargo:rerun-if-changed=src/bpf");
}
