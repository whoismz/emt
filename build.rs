use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let bpf_src = Path::new("src/ebpf/bpf/memory_tracer.bpf.c");
    let vmlinux_path = Path::new("src/ebpf/bpf/vmlinux.h");

    // Rerun build if these files change
    println!("cargo:rerun-if-changed={}", bpf_src.display());
    println!("cargo:rerun-if-changed={}", vmlinux_path.display());

    // Try to generate vmlinux.h if it does not exist
    if !vmlinux_path.exists() {
        let status = Command::new("bpftool")
            .args([
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/vmlinux",
                "format",
                "c",
            ])
            .output()
            .expect("Failed to execute bpftool to generate vmlinux.h");

        if !status.status.success() {
            eprintln!(
                "bpftool failed:\n{}",
                String::from_utf8_lossy(&status.stderr)
            );
            panic!("Could not generate vmlinux.h");
        }

        fs::write(vmlinux_path, &status.stdout).expect("Failed to write vmlinux.h to file");
    }

    // Build BPF object using clang
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bpf_out = out_dir.join("memory_tracer.bpf.o");

    let status = Command::new("clang")
        .args([
            "-g",
            "-O2",
            "-target",
            "bpf",
            "-D__TARGET_ARCH_x86",
            "-Wall",
            "-Werror",
            "-I",
            "src/bpf", // include vmlinux.h
            "-c",
        ])
        .arg(bpf_src)
        .arg("-o")
        .arg(&bpf_out)
        .status()
        .expect("Failed to execute clang");

    if !status.success() {
        panic!("Failed to compile BPF program");
    }
}
