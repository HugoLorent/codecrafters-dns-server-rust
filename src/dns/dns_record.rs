use bytes::{BufMut, BytesMut};
use std::net::Ipv4Addr;

// Structure for DNS Resource Records (answers)
pub struct DnsRecord {
    pub name: Vec<u8>,    // Domain name this record refers to
    pub record_type: u16, // Type of record (1 = A, 28 = AAAA, etc.)
    pub class: u16,       // Class of the record (1 = IN for Internet)
    pub ttl: u32,         // Time to live in seconds
    pub rdata: Vec<u8>,   // Record data (depends on type)
}

impl DnsRecord {
    // Create a new A record (IPv4 address) for a domain
    pub fn new(domain_name: Vec<u8>, ipv4: Ipv4Addr) -> Self {
        // Convert IPv4 address to bytes
        let ip_bytes = ipv4.octets().to_vec();

        DnsRecord {
            name: domain_name,
            record_type: 1, // A record
            class: 1,       // IN (Internet)
            ttl: 60,        // 60 seconds TTL
            rdata: ip_bytes,
        }
    }

    // Serialize the record to bytes
    pub fn to_bytes(&self) -> BytesMut {
        let mut bytes = BytesMut::new();

        // Put the domain name this record refers to
        bytes.extend_from_slice(&self.name);

        // Put record type, class, TTL
        bytes.put_u16(self.record_type);
        bytes.put_u16(self.class);
        bytes.put_u32(self.ttl);

        // Put the length of the record data
        bytes.put_u16(self.rdata.len() as u16);

        // Put the record data itself
        bytes.extend_from_slice(&self.rdata);

        bytes
    }

    // Helper to create a record for codecrafters.io pointing to 8.8.8.8
    pub fn default_codecrafters_record() -> Self {
        // Use the same domain name encoding as in the question
        let domain = super::dns_question::DnsQuestion::encode_domain_name("codecrafters.io");
        let ip = Ipv4Addr::new(8, 8, 8, 8); // 8.8.8.8 (Google DNS)

        Self::new(domain, ip)
    }
}
