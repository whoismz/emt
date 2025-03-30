use anyhow::{Context, Result};
use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

use emt::trace_process;

struct Cli {
    pid: Option<i32>,
    command: Option<String>,
    output: PathBuf,
    save_content: bool,
    duration: u64,
}

impl Cli {
    fn parse() -> Result<Self> {
        let args: Vec<String> = env::args().collect();

        let mut pid = None;
        let mut command = None;
        let mut output = PathBuf::from("./trace_output");
        let mut save_content = false;
        let mut duration = 0;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-p" | "--pid" => {
                    i += 1;
                    if i < args.len() {
                        pid = Some(i32::from_str(&args[i]).context("Invalid PID")?);
                    }
                }
                "-c" | "--command" => {
                    i += 1;
                    if i < args.len() {
                        command = Some(args[i].clone());
                    }
                }
                "-o" | "--output" => {
                    i += 1;
                    if i < args.len() {
                        output = PathBuf::from(&args[i]);
                    }
                }
                "-s" | "--save-content" => {
                    save_content = true;
                }
                "-d" | "--duration" => {
                    i += 1;
                    if i < args.len() {
                        duration = u64::from_str(&args[i]).context("Invalid duration")?;
                    }
                }
                "-h" | "--help" => {
                    println!("Linux userspace executable memory tracer");
                    println!("Usage: emt-cli [OPTIONS]");
                    println!("Options:");
                    println!("  -p, --pid PID                Process ID to trace");
                    println!("  -c, --command COMMAND        Command to execute and trace");
                    println!(
                        "  -o, --output DIR             Output directory for trace logs (default: ./trace_output)"
                    );
                    println!("  -s, --save-content           Save memory content");
                    println!(
                        "  -d, --duration SECONDS       Duration to trace in seconds (0 = trace until Ctrl+C)"
                    );
                    println!("  -h, --help                   Print help information");
                    std::process::exit(0);
                }
                _ => {
                    eprintln!("Unknown option: {}", args[i]);
                    eprintln!("Use --help for usage information");
                    std::process::exit(1);
                }
            }
            i += 1;
        }

        Ok(Self {
            pid,
            command,
            output,
            save_content,
            duration,
        })
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse()?;

    // get process ID to trace
    let pid = match (cli.pid, cli.command) {
        (Some(pid), None) => pid,
        (None, Some(cmd)) => {
            // if command is provided, start it and get PID
            let cmd_parts: Vec<&str> = cmd.split_whitespace().collect();
            let child = Command::new(cmd_parts[0])
                .args(&cmd_parts[1..])
                .spawn()
                .context("Failed to execute command")?;

            let pid = child.id() as i32;
            println!("Started process with PID: {}", pid);

            std::mem::forget(child);

            pid
        }
        _ => {
            eprintln!("Either --pid or --command must be specified");
            eprintln!("Use --help for usage information");
            std::process::exit(1);
        }
    };

    std::fs::create_dir_all(&cli.output).context("Failed to create output directory")?;

    println!("Starting memory tracer for PID: {}", pid);
    println!("Output directory: {}", cli.output.display());
    if cli.save_content {
        println!("Memory content will be saved");
    }

    let tracer = trace_process(pid, &cli.output, cli.save_content)
        .context("Failed to start memory tracer")?;

    // set up duration timeout or wait for Ctrl+C
    if cli.duration > 0 {
        println!("Tracing for {} seconds...", cli.duration);
        std::thread::sleep(std::time::Duration::from_secs(cli.duration));
        println!("Trace duration completed");
    } else {
        println!("Tracing process {} (press Ctrl+C to stop)...", pid);
        let (tx, rx) = std::sync::mpsc::channel();
        ctrlc::set_handler(move || {
            let _ = tx.send(());
        })?;

        // wait for Ctrl+C
        let _ = rx.recv();
        println!("Received Ctrl+C, stopping tracer");
    }

    drop(tracer);

    println!(
        "Tracing completed, results saved to: {}",
        cli.output.display()
    );
    Ok(())
}
