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

    // Parse a DNS record from bytes
    pub fn from_bytes(bytes: &[u8], start_pos: usize) -> Result<(Self, usize), &'static str> {
        if bytes.len() <= start_pos {
            return Err("Buffer too small for record");
        }

        // Parse the domain name
        let (name, name_bytes_consumed) =
            super::dns_question::DnsQuestion::parse_name_from(bytes, start_pos)?;

        // Calculate position after the name
        let record_start = start_pos + name_bytes_consumed;

        // Make sure we have enough bytes for the fixed part of the record (10 bytes):
        // TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2)
        if bytes.len() < record_start + 10 {
            return Err("Buffer too small for record fields");
        }

        // Parse the record fields
        let record_type = ((bytes[record_start] as u16) << 8) | (bytes[record_start + 1] as u16);
        let class = ((bytes[record_start + 2] as u16) << 8) | (bytes[record_start + 3] as u16);

        let ttl = ((bytes[record_start + 4] as u32) << 24)
            | ((bytes[record_start + 5] as u32) << 16)
            | ((bytes[record_start + 6] as u32) << 8)
            | (bytes[record_start + 7] as u32);

        let rdlength = ((bytes[record_start + 8] as u16) << 8) | (bytes[record_start + 9] as u16);

        // Make sure we have enough bytes for the record data
        if bytes.len() < record_start + 10 + rdlength as usize {
            return Err("Buffer too small for record data");
        }

        // Extract the record data
        let mut rdata = Vec::with_capacity(rdlength as usize);
        rdata.extend_from_slice(&bytes[record_start + 10..record_start + 10 + rdlength as usize]);

        // Calculate total bytes consumed
        let total_consumed = name_bytes_consumed + 10 + rdlength as usize;

        Ok((
            DnsRecord {
                name,
                record_type,
                class,
                ttl,
                rdata,
            },
            total_consumed,
        ))
    }

    // Helper to create a record for codecrafters.io pointing to 76.76.21.21
    pub fn default_codecrafters_record() -> Self {
        // Use the same domain name encoding as in the question
        let domain = super::dns_question::DnsQuestion::encode_domain_name("codecrafters.io");
        let ip = Ipv4Addr::new(76, 76, 21, 21); // 76.76.21.21 (Expected IP for codecrafters.io)

        Self::new(domain, ip)
    }
}
