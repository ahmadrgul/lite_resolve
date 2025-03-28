#include "dns_request.h"

int send_dns_query(const int sockfd, const char *server_ip, const uint8_t *query, size_t query_len){

    // internet socket address
    struct sockaddr_in server_addr;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
    socklen_t server_addr_len = sizeof(server_addr);

    // send query through given socket
    if (sendto(sockfd, query, query_len, 0, (struct sockaddr*)&server_addr, server_addr_len) < 0){
        perror("Query Sending Failure\n");
        exit(1);
    }

    return sockfd;
}

int build_dns_question(const char *domain_name, const enum Type query_type, uint8_t *buffer) {
    // offset from start of question section
    int offset = 0;

    // qname field of question
    char *encoded_domain = encode_domain(domain_name);
    int encoded_len = strlen(encoded_domain) + 1;
    memcpy(buffer + offset, encoded_domain, encoded_len);
    offset += encoded_len;
    // free(encoded_domain);

    // type and class fields of question
    DNS_question *question = malloc(sizeof(DNS_question));
    question->q_type = htons(query_type);
    question->q_class = htons(IN);
    memcpy(buffer + offset, question, sizeof(DNS_question));
    offset += sizeof(DNS_question);
    free(question);

    return offset;
}

int build_dns_query(const char *query_target, const enum Type query_type, uint8_t *query_buffer, size_t buffer_size, const uint16_t id){
    // offset from start of the query_buffer
    int offset = 0;

    // header section 
    DNS_header *header = calloc(1, sizeof(DNS_header));
    header->id = id;
    uint16_t qr_flag = 0x0100;
    // uint16_t opcode_flag = 0;
    // uint16_t aa_flag = 0x0000;
    // uint16_t tc_flag = 0x0000;
    // uint16_t rd_flag = 0x0100;
    // uint16_t ra_flag = 0x0000;
    // uint16_t z_flag  = 0x0000;
    // uint16_t rcode_flag = 0x0000;
    header->flags = htons(qr_flag);
    header->qd_count = htons(1);
    // header->an_count = 0;
    // header->ns_count = 0;
    // header->ar_count = 0;
    // copy the built header to buffer and free header memory
    memcpy(query_buffer, header, sizeof(DNS_header));
    offset += sizeof(DNS_header);
    free(header);
    
    // question section
    char *domain_name = malloc(strlen(query_target) + 1);
    if (query_type == PTR) {
        // for reverse lookup
        if(realloc(domain_name, strlen(query_target) + 14) == NULL) {
            printf("Memory Errro");
            exit(1);
        }
        int a, b, c, d;
        sscanf(query_target, "%d.%d.%d.%d", &a, &b, &c, &d);
        sprintf(domain_name, "%d.%d.%d.%d.in-addr.arpa", d, c, b, a); 
    } 
    int question_len = build_dns_question(query_target, query_type, query_buffer + offset);
    offset += question_len;

    // answer, authority and additional sections are not needed
    return offset;
}
