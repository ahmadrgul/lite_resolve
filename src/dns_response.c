#include "dns_response.h"

int recv_dns_response(const int sockfd, const char *server_ip, uint8_t *response, const size_t buffer_size){
    struct sockaddr_in server_addr;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
    socklen_t server_addr_len = sizeof(server_addr);

    int bytes_recieved = recvfrom(sockfd, response, buffer_size, 0, (struct sockaddr*)&server_addr, &server_addr_len);
    if (bytes_recieved < 0){
        perror("Response Receiving Failure\n");
        exit(EXIT_FAILURE);
    }

    return bytes_recieved;
}

DNSAnswerSet* parse_dns_response(const uint8_t *response_buffer, size_t buffer_size, const uint16_t id){
    // offset form the start of response buffer
    int offset = 0;
    
    // header section
    // cast the initial part of response to DNS_header struct
    DNS_header *header = (DNS_header *)(response_buffer);
    offset += sizeof(DNS_header);

    header->id = ntohs(header->id);
    if (ntohs(id) != header->id){
        perror("Didn't receive a valid DNS response");
        exit(EXIT_FAILURE);
    }

    // parsing flags
    header->flags = ntohs(header->flags);
    uint8_t qr_flag = (header->flags >> 15) & 0b1;
    // uint8_t opcode_flag = (header->flags >> 11) & 0b1111;
    // uint8_t aa = (header->flags >> 10) & 0b1;
    // uint8_t tc = (header->flags >> 9) & 0b1;
    // uint8_t rd = (header->flags >> 8) & 0b1;
    // uint8_t ra = (header->flags >> 7) & 0b1;
    // uint8_t z = (header->flags >> 4) & 0b1111;
    uint8_t rcode = header->flags & 0b1111;
    
    if (qr_flag != 1){
        perror("Didn't receive a valid DNS response");
        exit(EXIT_FAILURE);
    }

    if (rcode != 0){
        handle_rerror(rcode);
        exit(EXIT_FAILURE);
    }

    header->qd_count = ntohs(header->qd_count);
    header->an_count = ntohs(header->an_count);
    header->ns_count = ntohs(header->ns_count);
    header->ar_count = ntohs(header->ar_count);
    
    // question section: can have an_count number of questions, all of them can be processed the same way by looping, mostly we have only 1 question
    char **domain_labels = malloc(127 * sizeof(char *));
    offset += decode_domain(offset, response_buffer, domain_labels) + 1;
    char *qname = format_domain_name(domain_labels);

    uint16_t qtype = ntohs(*(uint16_t*)(response_buffer + offset));
    offset += 2;
    uint16_t qclass = ntohs(*(uint16_t*)(response_buffer + offset));
    offset += 2;
    
    // answer, authority and additional section
    DNSAnswerSet *res = build_ans_set();
    process_rr(header->an_count, 1, response_buffer, &offset, qtype, res);
    process_rr(header->ns_count, 2, response_buffer, &offset, qtype, res);
    process_rr(header->ar_count, 3, response_buffer, &offset, qtype, res);

    return res;
}