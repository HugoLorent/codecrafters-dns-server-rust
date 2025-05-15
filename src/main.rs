#[allow(unused_imports)]
use std::net::UdpSocket;

use dns::DnsMessage;

mod dns;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    println!("DNS Server listening on 127.0.0.1:2053");

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                // Extract request id (2 first bytes)
                let request_id = if size >= 2 {
                    ((buf[0] as u16) << 8) | (buf[1] as u16)
                } else {
                    // Fallback if request is too short
                    0
                };

                // Create a simple DNS response
                let dns_response = DnsMessage::new(request_id);
                let response_bytes = dns_response.to_bytes();

                // Send the response
                udp_socket
                    .send_to(&response_bytes, source)
                    .expect("Failed to send response");

                println!("Sent response to {}", source);
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
