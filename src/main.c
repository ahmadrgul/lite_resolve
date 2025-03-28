#include"dns_utils.h"
#include"dns_request.h"
#include"dns_response.h"
#include<errno.h>

int main(int argc, char *argv[]){
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: ./resolve [type] query\n");
        exit(EXIT_FAILURE);
    }

    UserQuery user_query = parseUserQuery(argc, argv);
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
    uint8_t *request = calloc(1, 512);

    uint16_t id = rand() % 65535;
    int req_len = build_dns_query(user_query.query, user_query.type, request, 512, id);
    send_dns_query(sockfd, DNS_SERVER, request, req_len);

    uint8_t *response = calloc(1, 512);
    int resposne_len = recv_dns_response(sockfd, DNS_SERVER, response, 512);
    DNSAnswerSet *answers = parse_dns_response(response, resposne_len, id);


    for (int type = TYPES_COUNT-1; type >= 0; type--) {
        int i = 0;
        if (answers->count[type]-1 >= 0) printf("Resolved:\n");

        while (i < answers->count[type]) {
            printf("%s\n", answers->answers[type][i]);
            i++;
        }
    }
    
    free_ans_set(answers);

    return 0;
}