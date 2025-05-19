#[allow(unused_imports)]
use std::net::UdpSocket;

use dns::dns_header::DnsHeader;
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

                // Parse the DNS header
                match DnsHeader::from_bytes(&buf[..size]) {
                    Ok(header) => {
                        println!("Parsed DNS header:");
                        println!("  ID: {}", header.id);
                        println!("  OPCODE: {}", header.opcode());
                        println!("  RD: {}", header.recursion_desired());
                        println!("  Questions: {}", header.qdcount);

                        // Create a DNS response based on the request header
                        let dns_response = DnsMessage::new_response_from_request(&header);
                        let response_bytes = dns_response.to_bytes();

                        // Send the response
                        udp_socket
                            .send_to(&response_bytes, source)
                            .expect("Failed to send response");

                        println!("Sent response to {}", source);
                    }
                    Err(e) => {
                        eprintln!("Failed to parse DNS header: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
