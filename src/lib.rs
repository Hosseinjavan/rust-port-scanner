use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

pub struct ScanConfig {
    pub target: IpAddr,
    pub start_port: u16,
    pub end_port: u16,
    pub threads: usize,
    pub timeout: Duration,
}

pub fn scan_port(target: IpAddr, port: u16, timeout: Duration) -> bool {
    let socket_address = SocketAddr::new(target, port);
    TcpStream::connect_timeout(&socket_address, timeout).is_ok()
}

pub fn run_scanner(config: ScanConfig) -> Vec<u16> {
    let (tx, rx) = mpsc::channel();
    let mut open_ports = Vec::new();
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
                if scan_port(target, port, timeout) {
                    tx_clone.send(port).unwrap_or_default();
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

    for open_port in rx {
        open_ports.push(open_port);
    }

    open_ports.sort();
    open_ports
}