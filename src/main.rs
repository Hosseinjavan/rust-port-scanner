use std::env;
use std::fs::File;
use std::io::Write;
use std::process;
use std::time::{Duration, Instant};
use rust_port_scanner::{resolve_target, run_scanner, ScanConfig};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        eprintln!("Usage: cargo run <TARGET_DOMAIN_OR_IP> <START_PORT> <END_PORT> [THREADS] [OUTPUT_FILE]");
        eprintln!("Example: cargo run scanme.nmap.org 1 100 50 results.txt");
        process::exit(1);
    }

    let target_input = &args[1];
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

    print!("Resolving target '{}'... ", target_input);
    let resolved_ip = match resolve_target(target_input) {
        Some(ip) => {
            println!("OK ({})", ip);
            ip
        }
        None => {
            println!("FAILED");
            eprintln!("Error: Could not resolve target hostname or IP address.");
            process::exit(1);
        }
    };

    println!("=================================================================");
    println!("        Advanced Concurrent Port Scanner & Banner Grabber        ");
    println!("Target Input : {}", target_input);
    println!("Resolved IP  : {}", resolved_ip);
    println!("Port Range   : {}-{}", start_port, end_port);
    println!("Threads      : {}", threads);
    println!("=================================================================");

    let config = ScanConfig {
        target: target_input.clone(),
        start_port,
        end_port,
        threads,
        timeout: Duration::from_millis(500),
    };

    let start_time = Instant::now();
    let open_ports = run_scanner(config, &resolved_ip);
    let duration = start_time.elapsed();

    println!("\n--- Scan Results ---");
    if open_ports.is_empty() {
        println!("No open ports found in specified range.");
    } else {
        println!("{:<8} {:<8} {:<12} {:<30}", "PORT", "STATE", "SERVICE", "BANNER / RESPONSE");
        println!("-----------------------------------------------------------------");
        for res in &open_ports {
            println!("{:<8} {:<8} {:<12} {:<30}", res.port, "OPEN", res.service, res.banner);
        }
    }

    println!("-----------------------------------------------------------------");
    println!("Scan finished in {:.2?}", duration);

    if let Some(file_path) = output_file {
        if let Ok(mut file) = File::create(&file_path) {
            let _ = writeln!(file, "Scan Report for Target: {} ({})", target_input, resolved_ip);
            for res in &open_ports {
                let _ = writeln!(file, "Port {}: OPEN ({}) | Banner: {}", res.port, res.service, res.banner);
            }
            println!("Report successfully saved to: {}", file_path);
        }
    }
}