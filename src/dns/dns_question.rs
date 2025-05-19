use bytes::{BufMut, BytesMut};
use std::str;

#[derive(Clone)]
pub struct DnsQuestion {
    pub name: Vec<u8>,
    pub record_type: u16,
    pub class: u16,
}

impl DnsQuestion {
    // Create a default question for codecrafters.io
    pub fn new() -> Self {
        DnsQuestion {
            name: Self::encode_domain_name("codecrafters.io"),
            record_type: 1, // A record (IPv4 address)
            class: 1,       // IN (Internet)
        }
    }

    // Encode a domain name according to DNS protocol
    pub fn encode_domain_name(domain: &str) -> Vec<u8> {
        let mut encoded = Vec::new();

        for part in domain.split('.') {
            if !part.is_empty() {
                encoded.push(part.len() as u8);
                encoded.extend_from_slice(part.as_bytes());
            }
        }

        // End with a null byte
        encoded.push(0);

        encoded
    }

    // Parse a DNS question from bytes, returns the question and the number of bytes consumed
    pub fn from_bytes(bytes: &[u8], start_pos: usize) -> Result<(Self, usize), &'static str> {
        if bytes.len() <= start_pos {
            return Err("Buffer too small for question section");
        }

        // Parse the domain name
        let (name, bytes_consumed) = Self::parse_domain_name(bytes, start_pos)?;

        // Make sure we have enough bytes for the record type and class (4 bytes)
        let next_pos = start_pos + bytes_consumed;
        if bytes.len() < next_pos + 4 {
            return Err("Buffer too small for question record type and class");
        }

        // Parse record type and class
        let record_type = ((bytes[next_pos] as u16) << 8) | (bytes[next_pos + 1] as u16);
        let class = ((bytes[next_pos + 2] as u16) << 8) | (bytes[next_pos + 3] as u16);

        // Total bytes consumed: name + 4 (2 for type, 2 for class)
        let total_consumed = bytes_consumed + 4;

        Ok((
            DnsQuestion {
                name,
                record_type,
                class,
            },
            total_consumed,
        ))
    }

    // Helper function to parse a domain name
    fn parse_domain_name(bytes: &[u8], start_pos: usize) -> Result<(Vec<u8>, usize), &'static str> {
        let mut position = start_pos;
        let mut name = Vec::new();
        let mut length = bytes[position];

        // Copy the entire encoded name (including length bytes and terminating zero)
        while length != 0 {
            name.push(length);

            // Check for buffer overflow
            if position + 1 + length as usize > bytes.len() {
                return Err("Domain name exceeds buffer size");
            }

            // Copy the label
            name.extend_from_slice(&bytes[position + 1..position + 1 + length as usize]);

            // Move to next label
            position += 1 + length as usize;

            // Check for buffer overflow again
            if position >= bytes.len() {
                return Err("Unexpected end of domain name");
            }

            length = bytes[position];
        }

        // Add the terminating zero
        name.push(0);

        // Calculate bytes consumed: position - start_pos + 1 for the final zero byte
        let bytes_consumed = position - start_pos + 1;

        Ok((name, bytes_consumed))
    }

    // For debugging: decode the domain name to a human-readable form
    pub fn decode_name(&self) -> Result<String, &'static str> {
        let mut result = String::new();
        let mut i = 0;

        while i < self.name.len() {
            let length = self.name[i] as usize;
            if length == 0 {
                break; // End of domain name
            }

            if !result.is_empty() {
                result.push('.');
            }

            if i + 1 + length > self.name.len() {
                return Err("Invalid domain name encoding");
            }

            match str::from_utf8(&self.name[i + 1..i + 1 + length]) {
                Ok(label) => result.push_str(label),
                Err(_) => return Err("Non-UTF8 domain name label"),
            }

            i += 1 + length;
        }

        Ok(result)
    }

    // Serialize the question to bytes
    pub fn to_bytes(&self) -> BytesMut {
        let mut bytes = BytesMut::new();

        // Put the domain name bytes
        bytes.extend_from_slice(&self.name);

        // Put record type and class
        bytes.put_u16(self.record_type);
        bytes.put_u16(self.class);

        bytes
    }
}
