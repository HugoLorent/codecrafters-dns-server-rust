mod dns_header;
mod dns_question;
mod dns_record;

use bytes::BytesMut;
use dns_header::DnsHeader;
use dns_question::DnsQuestion;
use dns_record::DnsRecord;

pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
}

impl DnsMessage {
    pub fn new(request_id: u16) -> Self {
        // Create a question for codecrafters.io
        let dns_questions = vec![DnsQuestion::new()];

        // Create an answer with the IP address 8.8.8.8
        let dns_answers = vec![DnsRecord::default_codecrafters_record()];

        // Create header with appropriate counts
        let header = DnsHeader::new(
            request_id,
            dns_questions.len() as u16,
            dns_answers.len() as u16,
        );

        DnsMessage {
            header,
            questions: dns_questions,
            answers: dns_answers,
        }
    }

    // Serialize the message to bytes
    pub fn to_bytes(&self) -> BytesMut {
        let mut bytes = self.header.to_bytes();

        // Add question section
        for question in &self.questions {
            let question_bytes = question.to_bytes();
            bytes.extend_from_slice(&question_bytes);
        }

        // Add answer section
        for answer in &self.answers {
            let answer_bytes = answer.to_bytes();
            bytes.extend_from_slice(&answer_bytes);
        }

        bytes
    }
}
