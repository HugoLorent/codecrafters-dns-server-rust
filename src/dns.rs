pub mod dns_header;
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
    // Parse a complete DNS message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        // Parse the header first
        let header = DnsHeader::from_bytes(bytes)?;

        // Start parsing questions from byte 12 (end of header)
        let mut position = 12;
        let mut questions = Vec::new();

        // Parse all questions
        for _ in 0..header.qdcount {
            let (question, bytes_consumed) = DnsQuestion::from_bytes(bytes, position)?;
            questions.push(question);
            position += bytes_consumed;
        }

        // For this step, we'll ignore parsing answers, authorities, and additionals

        Ok(DnsMessage {
            header,
            questions,
            answers: vec![], // Empty for now
        })
    }

    // Create a response for specific questions
    pub fn new(request_header: &DnsHeader, questions: Vec<DnsQuestion>) -> Self {
        // Create answers for each question
        let mut answers = Vec::new();

        for question in &questions {
            // Only respond to A record queries (type 1) for now
            if question.record_type == 1 {
                // Try to decode the domain name for debugging
                if let Ok(domain_name) = question.decode_name() {
                    println!("Creating answer for domain: {}", domain_name);
                }

                // Create an answer with Google's DNS IP (8.8.8.8)
                answers.push(DnsRecord::new(question.name.clone(), [8, 8, 8, 8].into()));
            }
        }

        // Create response header
        let header = DnsHeader::new(request_header, questions.len() as u16, answers.len() as u16);

        DnsMessage {
            header,
            questions,
            answers,
        }
    }

    // Create a response based on a request message
    pub fn new_response_from_request(request: &DnsMessage) -> Self {
        Self::new(&request.header, request.questions.clone())
    }

    // Create a response from just the header (fallback if question parsing fails)
    pub fn new_response_from_request_header(request_header: &DnsHeader) -> Self {
        // Create a default question
        let dns_questions = vec![DnsQuestion::new()];

        // Create an answer
        let dns_answers = vec![DnsRecord::default_codecrafters_record()];

        // Create response header
        let header = DnsHeader::new(
            request_header,
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
