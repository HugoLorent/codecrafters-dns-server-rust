mod dns_header;
mod dns_question;

use bytes::BytesMut;
use dns_header::DnsHeader;
use dns_question::DnsQuestion;

pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
}

impl DnsMessage {
    pub fn new(request_id: u16) -> Self {
        let dns_questions = vec![DnsQuestion::new()];
        DnsMessage {
            header: DnsHeader::new(request_id, dns_questions.len() as u16),
            questions: dns_questions,
        }
    }

    // Serialize the message to bytes
    pub fn to_bytes(&self) -> BytesMut {
        let mut bytes = self.header.to_bytes();

        for question in &self.questions {
            let question_bytes = question.to_bytes();
            bytes.extend_from_slice(&question_bytes);
        }

        bytes
    }
}
