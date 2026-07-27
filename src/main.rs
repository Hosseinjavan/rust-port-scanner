use std::env;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::process;
use std::time::{Duration, Instant};
use rust_port_scanner::{run_scanner, ScanConfig};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        eprintln!("Usage: cargo run <IP_ADDR> <START_PORT> <END_PORT> [THREADS] [OUTPUT_FILE]");
        eprintln!("Example: cargo run 127.0.0.1 1 1000 50 results.txt");
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

    let output_file = if args.len() >= 6 {
        Some(args[5].clone())
    } else {
        None
    };

    println!("===========================================");
    println!("  Advanced Network Port & Service Scanner  ");
    println!("Target IP  : {}", target);
    println!("Port Range : {}-{}", start_port, end_port);
    println!("Threads    : {}", threads);
    println!("===========================================");

    let config = ScanConfig {
        target,
        start_port,
        end_port,
        threads,
        timeout: Duration::from_millis(400),
    };

    let start_time = Instant::now();
    let open_ports = run_scanner(config);
    let duration = start_time.elapsed();

    println!("\n--- Scan Results ---");
    if open_ports.is_empty() {
        println!("No open ports found in specified range.");
    } else {
        println!("{:<10} {:<10} {:<15}", "PORT", "STATE", "SERVICE");
        println!("-------------------------------------------");
        for res in &open_ports {
            println!("{:<10} {:<10} {:<15}", res.port, "OPEN", res.service);
        }
    }

    println!("-------------------------------------------");
    println!("Scan completed in {:.2?}", duration);

    // ذخیره گزارش در فایل در صورت درخواست کاربر
    if let Some(file_path) = output_file {
        if let Ok(mut file) = File::create(&file_path) {
            let _ = writeln!(file, "Scan Report for Target: {}", target);
            for res in &open_ports {
                let _ = writeln!(file, "Port {}: OPEN ({})", res.port, res.service);
            }
            println!("Report successfully saved to: {}", file_path);
        }
    }
}