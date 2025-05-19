use std::env;
#[allow(unused_imports)]
use std::net::UdpSocket;

use dns::dns_header::DnsHeader;
use dns::DnsMessage;

mod dns;

fn main() {
    // Check if the program was run with a resolver address
    let args: Vec<String> = env::args().collect();
    let resolver_addr = if args.len() > 1 {
        // Check if the argument is "--resolver"
        if args[1] == "--resolver" {
            // If there's another argument after "--resolver", use it
            if args.len() > 2 {
                args[2].clone()
            } else {
                // Default to Google's DNS server if no resolver is specified
                String::from("8.8.8.8:53")
            }
        } else {
            // Use the provided resolver
            args[1].clone()
        }
    } else {
        // Default to Google's DNS server
        String::from("8.8.8.8:53")
    };

    println!("Using DNS resolver: {}", resolver_addr);

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    println!("DNS Server listening on 127.0.0.1:2053");

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                // Try to parse the complete DNS message
                match DnsMessage::from_bytes(&buf[..size]) {
                    Ok(request) => {
                        println!("Parsed DNS message:");
                        println!("  ID: {}", request.header.id);
                        println!("  Questions: {}", request.header.qdcount);

                        // Log the domain names with additional details
                        for (i, question) in request.questions.iter().enumerate() {
                            if let Ok(domain) = question.decode_name() {
                                println!("  Question {}: {} (Type: {}, Class: {}, Name length: {} bytes)",
                                    i + 1, domain, question.record_type, question.class, question.name.len());
                            } else {
                                println!(
                                    "  Question {}: <failed to decode> (Type: {}, Class: {})",
                                    i + 1,
                                    question.record_type,
                                    question.class
                                );
                            }
                        }

                        // Forward the query to the external DNS server
                        match DnsMessage::forward_query(&request, &resolver_addr) {
                            Ok(forwarded_response) => {
                                println!("Received response from external DNS server");
                                println!("  Answers: {}", forwarded_response.header.ancount);

                                // Send the forwarded response to the original client
                                let response_bytes = forwarded_response.to_bytes();
                                udp_socket
                                    .send_to(&response_bytes, source)
                                    .expect("Failed to send forwarded response");

                                println!("Forwarded response to {}", source);
                            }
                            Err(e) => {
                                eprintln!("Failed to forward query: {}", e);

                                // Fall back to our own response
                                let response = DnsMessage::new_response_from_request(&request);
                                let response_bytes = response.to_bytes();
                                udp_socket
                                    .send_to(&response_bytes, source)
                                    .expect("Failed to send fallback response");

                                println!("Sent fallback response to {}", source);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to parse DNS message: {}", e);

                        // Fall back to header-only parsing if full message parsing fails
                        if let Ok(header) = DnsHeader::from_bytes(&buf[..size]) {
                            // Create a simple response based on just the header
                            let response = DnsMessage::new_response_from_request_header(&header);
                            udp_socket
                                .send_to(&response.to_bytes(), source)
                                .expect("Failed to send fallback response");
                        }
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
