// examples/diagnostic.rs
use emt::{BpfTracer, MemoryAnalyzer};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    println!("EMT 诊断工具 - 检查组件是否正常运行");
    
    // 1. 检查当前进程
    let pid = std::process::id() as i32;
    println!("当前进程 PID: {}", pid);
    
    // 2. 测试内存分析器
    println!("\n---测试内存分析器---");
    let analyzer = MemoryAnalyzer::new(pid);
    match analyzer.get_executable_pages() {
        Ok(pages) => println!("✓ 找到 {} 个可执行内存页", pages.len()),
        Err(e) => println!("✗ 获取内存页失败: {}", e),
    }
    
    // 3. 测试 BPF 跟踪器
    println!("\n---测试 BPF 跟踪器---");
    let (tx, rx) = channel();
    match BpfTracer::new(tx, pid) {
        Ok(mut tracer) => {
            println!("✓ BPF 跟踪器创建成功");
            
            match tracer.start() {
                Ok(_) => println!("✓ BPF 跟踪器启动成功"),
                Err(e) => println!("✗ BPF 跟踪器启动失败: {}", e),
            }
            
            println!("等待事件...");
            for _ in 0..3 {
                match tracer.poll(1000) {
                    Ok(_) => print!("."),
                    Err(e) => println!("\n✗ 轮询失败: {}", e),
                }
            }
            println!();
            
            // 检查是否收到任何事件
            let event_count = rx.try_iter().count();
            println!("收到 {} 个事件", event_count);
            
            match tracer.stop() {
                Ok(_) => println!("✓ BPF 跟踪器停止成功"),
                Err(e) => println!("✗ BPF 跟踪器停止失败: {}", e),
            }
        },
        Err(e) => println!("✗ BPF 跟踪器创建失败: {}", e),
    }
    
    println!("\n诊断完成");
    Ok(())
}
