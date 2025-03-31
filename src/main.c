#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "utils.h"
#include "query.h"
#include "response.h"
#include "packet.h"

int main(int argc, char *argv[]){
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: ./resolve [type] query\n");
        exit(EXIT_FAILURE);
    }

    UserQuery user_query = parse_user_query(argc, argv);
    if (user_query.type == UNKNOWN) {
        fprintf(stderr, "Unknown type: %s", argv[1]);
        exit(EXIT_FAILURE);
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0){
        fprintf(stderr, "Error: Failed to create socket (errno: %d - %s)\n", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    srand(time(NULL));

    struct sockaddr_in server_addr;
    server_addr.sin_addr.s_addr = inet_addr(DNS_SERVER);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);

    DnsPacket query_packet = build_query(user_query);
    send_packet(sockfd, query_packet, server_addr);
    
    uint8_t buffer[512];
    recv_packet(sockfd, buffer, server_addr);
    DnsPacket response_packet = parse_packet(buffer);
    response_packet = ntoh_packet(response_packet);

    UserResponse *user_responses = build_user_responses(response_packet.answers, response_packet.header.an_count);
    
    for (int i = 0; i < response_packet.header.an_count; i++) {
        printf("--> %s\n", user_responses[i].answer);
    }
    
    free_user_responses(user_responses, response_packet.header.an_count);
    free_packet(response_packet);
    free_packet(query_packet);
    return 0;
}
