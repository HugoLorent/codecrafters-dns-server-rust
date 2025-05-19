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

                // Try to parse the complete DNS message
                match DnsMessage::from_bytes(&buf[..size]) {
                    Ok(request) => {
                        println!("Parsed DNS message:");
                        println!("  ID: {}", request.header.id);
                        println!("  Questions: {}", request.header.qdcount);

                        // Log the questions
                        for (i, question) in request.questions.iter().enumerate() {
                            if let Ok(domain) = question.decode_name() {
                                println!(
                                    "  Question {}: {} (Type: {}, Class: {})",
                                    i + 1,
                                    domain,
                                    question.record_type,
                                    question.class
                                );
                            } else {
                                println!(
                                    "  Question {}: <failed to decode> (Type: {}, Class: {})",
                                    i + 1,
                                    question.record_type,
                                    question.class
                                );
                            }
                        }

                        // Create a response with the parsed questions
                        let response = DnsMessage::new_response_from_request(&request);

                        println!("Sending response with {} answer(s)", response.answers.len());

                        // Send the response
                        let response_bytes = response.to_bytes();
                        udp_socket
                            .send_to(&response_bytes, source)
                            .expect("Failed to send response");

                        println!("Sent response to {}", source);
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
