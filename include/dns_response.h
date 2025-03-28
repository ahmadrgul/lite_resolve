#ifndef DNS_RESPONSE
#define DNS_RESPONSE
#include "dns_utils.h"

int recv_dns_response(const int sockfd, const char *server_ip, uint8_t *response, const size_t buffer_size);
DNSAnswerSet* parse_dns_response(const uint8_t *response_buffer, size_t response_length, const uint16_t id);


#endif