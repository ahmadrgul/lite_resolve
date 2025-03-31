#ifndef QUERY
#define QUERY

#include "utils.h"
#include "packet.h"
#include <arpa/inet.h>

DnsPacket build_query(UserQuery user_query);
int send_packet(int sockfd, DnsPacket packet, struct sockaddr_in sock_addr);

#endif