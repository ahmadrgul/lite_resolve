#include "query.h"
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

DnsPacket build_query(UserQuery user_query) {
    uint16_t query_id = rand() % 65535;
    uint16_t flags = 0x0100;
    DnsHeader header = build_header(query_id, flags, 1, 0, 0, 0);

    DnsQuestion question = build_question(user_query.query, user_query.type, 1);
    DnsQuestion questions[] = { question };
    // no need to consider other sections in query

    DnsPacket query_packet = build_packet(header, questions, NULL, NULL, NULL);
    return query_packet;
}

int send_packet(int sockfd, DnsPacket packet, struct sockaddr_in sock_addr) {
    uint8_t buffer[512];
    size_t query_len = sizeof_packet(packet);
    packet = hton_packet(packet);
    memcpy_packet(buffer, packet);

    ssize_t bytes_sent = sendto(sockfd, buffer, query_len, 0, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
    if (bytes_sent == -1) {
        fprintf(stderr, "Error: Failed to send packet (errno: %d - %s)\n", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }

    return 0;
}
