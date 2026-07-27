use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub is_open: bool,
    pub service: String,
}

pub struct ScanConfig {
    pub target: IpAddr,
    pub start_port: u16,
    pub end_port: u16,
    pub threads: usize,
    pub timeout: Duration,
}

// اسکن پورت همراه با تشخیص نام سرویس بر اساس پورت‌های معروف
pub fn scan_port(target: IpAddr, port: u16, timeout: Duration) -> Option<PortResult> {
    let socket_address = SocketAddr::new(target, port);
    
    if let Ok(mut stream) = TcpStream::connect_timeout(&socket_address, timeout) {
        let _ = stream.set_read_timeout(Some(timeout));
        
        let service = match port {
            21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
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

        Some(PortResult {
            port,
            is_open: true,
            service: service.to_string(),
        })
    } else {
        None
    }
}

pub fn run_scanner(config: ScanConfig) -> Vec<PortResult> {
    let (tx, rx) = mpsc::channel();
    let mut results = Vec::new();
    let mut current_port = config.start_port;

    while current_port <= config.end_port {
        let mut handlers = Vec::new();

        for _ in 0..config.threads {
            if current_port > config.end_port {
                break;
            }

            let tx_clone = tx.clone();
            let target = config.target;
            let port = current_port;
            let timeout = config.timeout;

            let handle = thread::spawn(move || {
                if let Some(res) = scan_port(target, port, timeout) {
                    tx_clone.send(res).unwrap_or_default();
                }
            });

            handlers.push(handle);
            current_port += 1;
        }

        for handle in handlers {
            let _ = handle.join();
        }
    }

    drop(tx);

    for res in rx {
        results.push(res);
    }

    results.sort_by_key(|r| r.port);
    results
}