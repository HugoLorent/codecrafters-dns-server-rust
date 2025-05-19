# DNS Server Implementation in Rust

A fully functional DNS server implemented in Rust as part of the [CodeCrafters DNS Server Challenge](https://codecrafters.io/challenges/dns-server).

## Features

- **DNS Protocol Support**: Properly parses and constructs DNS packets according to RFC standards
- **Query Resolution**: Responds to DNS queries with appropriate answers
- **Compression Support**: Handles DNS name compression in both parsing and response generation
- **Forwarding Server**: Can function as a forwarding DNS server, relaying queries to upstream DNS servers
- **Multiple Query Handling**: Supports requests with multiple questions

## Implementation Details

This DNS server is built with a clean, modular architecture:

- **Header Parsing**: Correctly handles DNS headers with proper bit manipulation
- **Question Parsing**: Parses domain names with support for compression pointers
- **Answer Construction**: Builds appropriate resource records
- **Error Handling**: Robust error handling for malformed packets and network issues

## Usage

```bash
# Run as a forwarding server
./your_program --resolver 8.8.8.8:53
