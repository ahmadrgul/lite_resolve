#ifndef DNS_REQUEST
#define DNS_REQUEST
#include"dns_utils.h"

int build_dns_question(const char *domain_name, const enum Type query_type, uint8_t *buffer);
int build_dns_query(const char *query_target, const enum Type query_type, uint8_t *query_buffer, size_t buffer_size, const uint16_t id);
int send_dns_query(const int sockfd, const char *server_ip, const uint8_t *query, size_t query_len);

#endif