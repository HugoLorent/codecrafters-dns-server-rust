use bytes::{BufMut, BytesMut};

pub struct DnsHeader {
    pub id: u16,      // Query identifier
    pub flags: u16,   // Combined flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
    pub qdcount: u16, // Question count
    pub ancount: u16, // Answer count
    pub nscount: u16, // Authority count
    pub arcount: u16, // Additional information count
}

impl DnsHeader {
    pub fn new(request_id: u16, question_count: u16, answer_count: u16) -> Self {
        // Flags: QR=1 (Response), everything else is 0
        // 1000 0000 0000 0000 = 0x8000
        let flags = 0x8000;

        DnsHeader {
            id: request_id,
            flags,
            qdcount: question_count,
            ancount: answer_count,
            nscount: 0,
            arcount: 0,
        }
    }

    pub fn to_bytes(&self) -> BytesMut {
        let mut bytes = BytesMut::with_capacity(12); // DNS header is 12 bytes

        bytes.put_u16(self.id);
        bytes.put_u16(self.flags);
        bytes.put_u16(self.qdcount);
        bytes.put_u16(self.ancount);
        bytes.put_u16(self.nscount);
        bytes.put_u16(self.arcount);

        bytes
    }
}
