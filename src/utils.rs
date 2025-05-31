use log::debug;
use std::time::SystemTime;

pub fn print_memory_content(content: &[u8], address: usize) {
    const BYTES_PER_ROW: usize = 16;
    for (i, chunk) in content.chunks(BYTES_PER_ROW).enumerate() {
        let mut hex_line = format!("0x{:08x}: ", address + i * BYTES_PER_ROW);

        for (j, byte) in chunk.iter().enumerate() {
            hex_line.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                hex_line.push(' ');
            }
        }

        if chunk.len() < BYTES_PER_ROW {
            let spaces = (BYTES_PER_ROW - chunk.len()) * 3 + if chunk.len() <= 8 { 1 } else { 0 };
            for _ in 0..spaces {
                hex_line.push(' ');
            }
        }

        hex_line.push_str(" | ");
        for &byte in chunk {
            if byte >= 32 && byte <= 126 {
                hex_line.push(byte as char);
            } else {
                hex_line.push('.');
            }
        }

        debug!("{}", hex_line);
    }
}

pub(crate) fn boot_time_seconds() -> u64 {
    let uptime_seconds = std::fs::read_to_string("/proc/uptime")
        .expect("Failed to read /proc/uptime")
        .split_whitespace()
        .next()
        .expect("Malformed /proc/uptime")
        .parse::<f64>()
        .expect("Uptime not a number");

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs_f64();

    (now - uptime_seconds) as u64
}
