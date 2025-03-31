#ifndef RESPONSE
#define RESPONSE

#include <arpa/inet.h>
#include <stdint.h>

int recv_packet(int sockfd, uint8_t buffer[], struct sockaddr_in sock_addr);

#endif