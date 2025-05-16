use bytes::{BufMut, BytesMut};

pub struct DnsQuestion {
    pub domain_name: Vec<u8>,
    pub record_type: u16,
    pub class: u16,
}

impl DnsQuestion {
    pub fn new() -> Self {
        DnsQuestion {
            domain_name: Self::encode_domain_name("codecrafters.io"),
            record_type: 1, // A record (IPv4 address)
            class: 1,       // IN (Internet)
        }
    }

    // Encode a domain name according to DNS protocol
    // Example: "codecrafters.io" becomes [12, 'c', 'o', 'd', 'e', 'c', 'r', 'a', 'f', 't', 'e', 'r', 's', 2, 'i', 'o', 0]
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

    // Serialize the question to bytes
    pub fn to_bytes(&self) -> BytesMut {
        let mut bytes = BytesMut::new();

        // Put the domain name bytes
        bytes.extend_from_slice(&self.domain_name);

        // Put record type and class
        bytes.put_u16(self.record_type);
        bytes.put_u16(self.class);

        bytes
    }
}
