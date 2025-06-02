use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::os::unix::io::AsRawFd;
use std::process;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn create_test_file(path: &str, size: usize) -> io::Result<()> {
    let mut file = File::create(path)?;

    let mut content = Vec::new();

    for i in 0..size {
        match i % 16 {
            0..=3 => content.push(0x90),
            4..=7 => content.push(0x48),
            8..=11 => content.push(0x31),
            12..=15 => content.push(0xC0),
            _ => content.push((i % 256) as u8),
        }
    }

    file.write_all(&content)?;
    file.sync_all()?;
    Ok(())
}

fn test_file_mapping() -> io::Result<()> {
    let test_file = "/tmp/emt_test_file.bin";
    let file_size = 4096 * 3;

    create_test_file(test_file, file_size)?;

    let file = OpenOptions::new().read(true).write(true).open(test_file)?;
    let fd = file.as_raw_fd();

    unsafe {
        let mapped_addr = libc::mmap(
            ptr::null_mut(),
            file_size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE,
            fd,
            0,
        );

        if mapped_addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        println!("mapping : {:p}, size: {}", mapped_addr, file_size);

        libc::munmap(mapped_addr, file_size);
    }

    // clean
    let _ = std::fs::remove_file(test_file);

    Ok(())
}

fn main() {
    println!("PID: {} Press Enter to start ...", process::id());

    let _ = io::stdin().lock().lines().next();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("Stopping...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl+C handler");

    if let Err(e) = test_file_mapping() {
        eprintln!("test failed: {}", e);
        return;
    }
}
