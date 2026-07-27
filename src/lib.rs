use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub is_open: bool,
    pub service: String,
    pub banner: String,
}

pub struct ScanConfig {
    pub target: String,
    pub start_port: u16,
    pub end_port: u16,
    pub threads: usize,
    pub timeout: Duration,
}

// تابع تبدیل دامنه یا IP به آدرس واقعی شبکه
pub fn resolve_target(target: &str) -> Option<String> {
    let formatted = format!("{}:80", target);
    if let Ok(mut addrs) = formatted.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Some(addr.ip().to_string());
        }
    }
    None
}

// اسکن پورت + دریافت Banner (پاسخ واقعی پورت)
pub fn scan_port(ip: &str, port: u16, timeout: Duration) -> Option<PortResult> {
    let address = format!("{}:{}", ip, port);
    
    // پارس کردن صحیح آدرس شبکه
    let socket_addr: SocketAddr = match address.parse() {
        Ok(addr) => addr,
        Err(_) => return None,
    };

    if let Ok(mut stream) = TcpStream::connect_timeout(&socket_addr, timeout) {
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));

        let service = match port {
            21 => "FTP",
            22 => "SSH",
            25 => "SMTP",
            53 => "DNS",
            80 => "HTTP",
            110 => "POP3",
            143 => "IMAP",
            443 => "HTTPS",
            3306 => "MySQL",
            5432 => "PostgreSQL",
            8080 => "HTTP-Proxy",
            _ => "Unknown",
        };

        // تلاش برای خواندن بایت‌های اولیه پاسخ (Banner Grabbing)
        let mut banner = String::from("N/A");
        if port == 80 || port == 8080 {
            let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n");
        }

        let mut buffer = [0; 64];
        if let Ok(bytes_read) = stream.read(&mut buffer) {
            if bytes_read > 0 {
                let raw_banner = String::from_utf8_lossy(&buffer[..bytes_read]);
                banner = raw_banner.lines().next().unwrap_or("N/A").trim().to_string();
            }
        }

        Some(PortResult {
            port,
            is_open: true,
            service: service.to_string(),
            banner,
        })
    } else {
        None
    }
}

pub fn run_scanner(config: ScanConfig, resolved_ip: &str) -> Vec<PortResult> {
    let (tx, rx) = mpsc::channel();
    let mut results = Vec::new();

    let total_ports = (config.end_port - config.start_port + 1) as usize;
    let scanned_counter = Arc::new(Mutex::new(0usize));
    let mut current_port = config.start_port;

    while current_port <= config.end_port {
        let mut handlers = Vec::new();

        for _ in 0..config.threads {
            if current_port > config.end_port {
                break;
            }

            let tx_clone = tx.clone();
            let ip = resolved_ip.to_string();
            let port = current_port;
            let timeout = config.timeout;
            let counter = Arc::clone(&scanned_counter);

            let handle = thread::spawn(move || {
                let res = scan_port(&ip, port, timeout);
                
                // به‌روزرسانی شمارنده زنده
                if let Ok(mut num) = counter.lock() {
                    *num += 1;
                    let percent = (*num as f32 / total_ports as f32) * 100.0;
                    print!("\rScanning Progress: {:.1}% ({}/{})", percent, *num, total_ports);
                    let _ = std::io::stdout().flush();
                }

                if let Some(r) = res {
                    tx_clone.send(r).unwrap_or_default();
                }
            });

            handlers.push(handle);
            current_port += 1;
        }

        for handle in handlers {
            let _ = handle.join();
        }
    }

    println!(); // رفتن به خط بعدی پس از اتمام درصد پیشرفت
    drop(tx);

    for res in rx {
        results.push(res);
    }

    results.sort_by_key(|r| r.port);
    results
}