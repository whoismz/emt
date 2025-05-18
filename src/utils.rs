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

        println!("{}", hex_line);

        if i >= 15 && content.len() > 16 * 16 {
            println!(
                "... (showing only first 16 lines of {} total)",
                (content.len() + BYTES_PER_ROW - 1) / BYTES_PER_ROW
            );
            break;
        }
    }
    println!();
}
