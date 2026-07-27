use std::env;
use std::net::IpAddr;
use std::process;
use std::time::{Duration, Instant};
use rust_port_scanner::{run_scanner, ScanConfig};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        eprintln!("Usage: cargo run <IP_ADDR> <START_PORT> <END_PORT> [THREADS]");
        eprintln!("Example: cargo run 127.0.0.1 1 1000 50");
        process::exit(1);
    }

    let target: IpAddr = match args[1].parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("Error: Invalid IP address format.");
            process::exit(1);
        }
    };

    let start_port: u16 = args[2].parse().unwrap_or(1);
    let end_port: u16 = args[3].parse().unwrap_or(1024);
    let threads: usize = if args.len() >= 5 {
        args[4].parse().unwrap_or(20)
    } else {
        20
    };

    println!("===========================================");
    println!("Starting Concurrent Network Port Scanner");
    println!("Target IP  : {}", target);
    println!("Port Range : {}-{}", start_port, end_port);
    println!("Threads    : {}", threads);
    println!("===========================================");

    let config = ScanConfig {
        target,
        start_port,
        end_port,
        threads,
        timeout: Duration::from_millis(500),
    };

    let start_time = Instant::now();
    let open_ports = run_scanner(config);
    let duration = start_time.elapsed();

    println!("\n--- Scan Results ---");
    if open_ports.is_empty() {
        println!("No open ports found.");
    } else {
        for port in &open_ports {
            println!("Port {:>5} : OPEN", port);
        }
    }

    println!("-------------------------------------------");
    println!("Scan finished in {:.2?}", duration);
}