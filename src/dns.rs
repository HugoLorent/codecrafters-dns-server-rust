mod dns_header;

use bytes::BytesMut;
use dns_header::DnsHeader;

pub struct DnsMessage {
    pub header: DnsHeader,
}

impl DnsMessage {
    pub fn new(request_id: u16) -> Self {
        DnsMessage {
            header: DnsHeader::new(request_id),
        }
    }

    // Serialize the message to bytes
    pub fn to_bytes(&self) -> BytesMut {
        self.header.to_bytes()
    }
}
