#include "response.h"

int recv_packet(int sockfd, uint8_t buffer[], struct sockaddr_in sock_addr) {
    socklen_t sock_addr_len = sizeof(sock_addr);
    ssize_t bytes_recvd = recvfrom(sockfd, buffer, 512, 0, (struct sockaddr*)&sock_addr, &sock_addr_len);
    return 0;
}