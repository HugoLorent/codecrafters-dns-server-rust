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
    // Create a response header based on a request header
    pub fn new(request_header: &DnsHeader, question_count: u16, answer_count: u16) -> Self {
        // Start with a copy of the request ID
        let id = request_header.id;

        // Extract OPCODE from request
        let opcode = (request_header.flags >> 11) & 0xF;

        // Extract RD from request
        let rd = (request_header.flags >> 8) & 0x1;

        // Build response flags:
        // QR = 1 (response)
        // OPCODE = copy from request
        // AA = 0 (not authoritative)
        // TC = 0 (not truncated)
        // RD = copy from request
        // RA = 0 (recursion not available)
        // Z = 0 (reserved)
        // RCODE = 0 if OPCODE is 0, else 4 (not implemented)

        let rcode = if opcode == 0 { 0 } else { 4 };

        // Bit positions:
        // 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0
        // QR OP OP OP OP AA TC RD RA Z  Z  Z  RC RC RC RC

        let flags = (1 << 15) |        // QR = 1
                   (opcode << 11) |         // OPCODE from request
                   (rd << 8) |              // RD from request
                   rcode; // RCODE based on OPCODE

        DnsHeader {
            id,
            flags,
            qdcount: question_count,
            ancount: answer_count,
            nscount: 0,
            arcount: 0,
        }
    }

    // Parse header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 12 {
            return Err("Header buffer too small");
        }

        // Extract fields from the buffer
        let id = ((bytes[0] as u16) << 8) | (bytes[1] as u16);
        let flags = ((bytes[2] as u16) << 8) | (bytes[3] as u16);
        let qdcount = ((bytes[4] as u16) << 8) | (bytes[5] as u16);
        let ancount = ((bytes[6] as u16) << 8) | (bytes[7] as u16);
        let nscount = ((bytes[8] as u16) << 8) | (bytes[9] as u16);
        let arcount = ((bytes[10] as u16) << 8) | (bytes[11] as u16);

        Ok(DnsHeader {
            id,
            flags,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
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
