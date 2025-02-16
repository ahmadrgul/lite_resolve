#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<time.h>

#define DNS_PORT 53
#define DNS_SERVER "8.8.8.8"

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
} DNS_header;

typedef struct {
    uint16_t q_type;
    uint16_t q_class;
} DNS_question;

typedef struct {
    char name[254];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlen;
    uint8_t *answer;
} Resource_Record;

int build_dns_query(const char *hostname, uint8_t *query, size_t buffer_size, uint16_t *id); // writes a dns query into given buffer
int encode_hostname(const char *hostname, uint8_t *encoded, size_t buffer_size); // stores encoded hostname in given buffer
void send_dns_query(const int sockfd, const char *server_ip, const uint8_t *query, size_t query_length); // sends the data in given buffer to give ip
int recv_dns_response(const int sockfd, const char *server_ip, uint8_t *response, size_t buffer_size); // receive data and stores in the given buffer
int parse_dns_response(const uint8_t *response, size_t response_length, const uint16_t id); // interprets data in reponse as dns response
int decode_hostname(const uint8_t *encoded, char *hostname, size_t buffer_size); // stores the decoded hostname in given buffer
int display_dns_record(Resource_Record record);


int display_dns_record(Resource_Record record){

    printf("Name: %s\n", record.name);

    // if its a type A record
    if (record.type == 1){
        printf("Address: ");
        for (int i = 0; i < record.rdlen; i++){
            printf("%d", record.answer[i]);
            if (i != record.rdlen - 1){
                printf(".");
            }
        }
        printf("\n");
    }
    else {
        printf("Not a type A record\n");
    }
}

void handle_rerror(uint8_t code){
    char *err;
    switch(code){
        case 1:
            err = "Format Error";
            break;
        case 2:
            err = "Server Failure";
            break;
        case 3:
            err = "The domain name queried doesn't exist";
            break;
        case 4:
            err = "The server doesn't support the requested query type";
            break;
        case 5:
            err = "Server refused to perfor query";
            break;
        case 9:
            err = "The server is not authorized to respond to query";
            break;
        default:
            err = "An error occured";
    }

    printf("\n%s...\n", err);
    exit(code);
}

int encode_hostname(const char *hostname, uint8_t *encoded, size_t buffer_size){
    int len = strlen(hostname);

    // if the size of buffer to store encoded_hostname to, is less than needed
    if (len + 2 > buffer_size){
        return -1;
    }

    int encoded_index = 0;

    // traverse the whole hostname character by character
    for (int i = 0; i < len; i++){

        // if character is not a dot, copy the character as it is
        // copy the entire hostname into encoded_hostname, excepting the dots
        // encoded_index is one greater than hostname index, since encoded_hostname contain label at start
        if (hostname[i] != '.'){
            encoded[++encoded_index] = hostname[i];
        }

        // if a dot is encountered, it means a label has ended
        else {

            // index (in hostname) of 'last character of last label copied'
            int j = i - 1;
            // length of the label last copied
            int label_len = 0;

            // calculate the length of last copied label
            while (j >= 0 && hostname[j] != '.') {
                ++label_len;
                --j;
            }
            
            // put the length of the label at the start of the label
            encoded[encoded_index - label_len] = (size_t)label_len;
            // incremenet encoded_index to leave blank place for the length of the next label
            encoded_index++;
        }
        
        // if this the last character
        // a label is ended without encountering a dot
        if (i == len - 1){
            // i = index of the last character of last copied label 
            int label_len = 0;
            while (i >= 0 && hostname[i] != '.') {
                ++label_len;
                --i;
            }
            encoded[encoded_index - label_len] = (size_t)label_len;
            encoded_index++;
            break;
        }
    }
    
    // put 0x00 at the end of encoded_hostname
    encoded[encoded_index + 1] = '\x00';

    uint8_t *buffer = calloc(1, strlen(hostname));
    return 0;
}

int decode_hostname(const uint8_t *encoded, char *hostname, size_t buffer_size){

    // pointer in encoded_hostname
    int i = 0;
    // pointer in hostname
    int hostname_index = 0;
    
    // traverse the entire encoded_hostname string label by label
    while (encoded[i] != '\x00'){
        // get the size of the label
        // and increment i to point to the first character of label
        size_t label_len = encoded[i++];

        // if the first two bits of label_len are 11, compression is used
        if ((label_len << 14) & 0b11 == 0b11) {
            return label_len & 0x3FFF;
        }

        // label pointer
        int j = 0;

        // traverse the entire label and store each character of label in hostname
        while (j < (int)label_len){
            hostname[hostname_index++] = encoded[i++];
            ++j;
        }

        // if this was not the last label 
        // if (hostname_index < buffer_size)
            hostname[hostname_index++] = '.';
    }

    // place string terminator at the place of data placed at the end of last label
    hostname[--hostname_index] = '\0';

    return (strlen(encoded) + 1);
}

int build_dns_query(const char *hostname, uint8_t *query, size_t buffer_size, uint16_t *id){
    // offset from start of the query_buffer
    int offset = 0;

    DNS_header *header = calloc(1, sizeof(DNS_header));
    // id is a random number between zero and 2^16
    *id = header->id = htons(rand() % 65536);

    // 16b of flags are divided as follows
    // Query/Response - 1b - 0 for query
    // Opcode - 4b
    // Authoritative Answer - 1b
    // Truncated Message - 1b
    // Recursion Desired - 1b
    // Recursion Avaiable - 1b
    // Reserved - 3b
    // Error Code - 4b
    // set the recursion desired flag 
    header->flags = htons(0x0100);

    // number of questions
    header->qd_count = htons(1);

    // copy header to query_buffer and increase offset
    memcpy(query, header, sizeof(DNS_header));
    offset += sizeof(DNS_header);

    // don't need this anymore since data is copied to real query buffer
    free(header);

    // now comes the next part of dns message i.e question
    // encode the given hostname in labels
    // directly give the query_buffer to put encoded hostname into it
    size_t encoded_hostname_len = strlen(hostname) + 2;
    if (encode_hostname(hostname, query + offset, encoded_hostname_len) < 0) {
        printf("Hostname encoding error...");
        return -1;
    }
    offset += encoded_hostname_len;

    // set the type and class of this question
    DNS_question *question = calloc(1, sizeof(DNS_question));
    question->q_type = htons(1);
    question->q_class = htons(1);

    // copy the question data into next free place in query_buffer
    memcpy(query + offset, question, sizeof(DNS_question));
    offset += sizeof(DNS_question);
    free(question);

    // return the size of the dns query message message
    return offset;
}

void send_dns_query(const int sockfd, const char *server_ip, const uint8_t *query, size_t query_len){
    
    // internet socket address
    struct sockaddr_in server_addr;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
    socklen_t server_addr_len = sizeof(server_addr);

    // send query through given socket
    if (sendto(sockfd, query, query_len, 0, (struct sockaddr*)&server_addr, server_addr_len) < 0){
        perror("Query Sending Failure\n");
        exit(EXIT_FAILURE);
    }

    return;
}

int recv_dns_response(const int sockfd, const char *server_ip, uint8_t *response, size_t buffer_size){

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

int parse_dns_response(const uint8_t *response, size_t buffer_size, const uint16_t id){
    
    int offset = 0;
    
    // cast the first part of response to DNS_header struct
    DNS_header *header = (DNS_header *)(response + offset);
    header->id = ntohs(header->id);

    // if the response id doesn't match query id 
    if (ntohs(id) != header->id){
        perror("Didn't receive a valid DNS response");
        exit(EXIT_FAILURE);
    }
    
    header->flags = ntohs(header->flags);

    // get the value of qr flag: 1st bit in flags
    uint8_t qr = (header->flags >> 15) & 1;
    // if qr is not 1 it means its not a response
    if (qr != 1){
        perror("Didn't receive a valid DNS response");
        exit(EXIT_FAILURE);
    }

    // get the value of error_code field from flags: last 4 bits in flags
    uint8_t rcode = 0b1111 & header->flags;
    // if there is an error
    if (rcode != 0){
        handle_rerror(rcode);
        exit(EXIT_FAILURE);
    }
    
    header->qd_count = ntohs(header->qd_count);
    header->an_count = ntohs(header->an_count);
    header->ns_count = ntohs(header->ns_count);
    header->ar_count = ntohs(header->ar_count);

    // increase offset from start of the reponse buffer to skip Header as it has been processed
    offset += sizeof(DNS_header);

    // question section consists of qd_count (from header) number of questions
    // question section in response is an exact copy of question section of the query
    // so skip over all questions
    for (int i = 0; i < header->qd_count; i++){
        // domain_ptr points to the first char in encoded_domain_name
        uint8_t *domain_ptr = response + offset;
        // skip over all the chars of encoded_domain_name
        while (*domain_ptr != 0x00) ++domain_ptr;
        // domain_ptr now points to last char in endoced_domain_name which is always 0x00
        offset = domain_ptr - response + 1;
        // skip 2B of type: q_type
        offset += 2;
        // skip 2B of class: q_class
        offset += 2;
    }

    // answer field consists of an_count number of resource records
    // for each resource record in the answers section
    for (int i = 0; i < header->an_count; i++){

        uint8_t *domain_ptr;
        char domain_name[254];

        // domain_name is pointer, not ecnoded_domain_name, if the first two bits are 11
        uint16_t start_octets = ntohs(*((uint16_t *)(response + offset)));

        // if its a pointer to encoded_domain
        if ((start_octets >> 14) & 0b11 == 0b11){
            // mask out the first two bits and the other is offset from start
            domain_ptr = response + (start_octets & 0x3FFF);
            decode_hostname(domain_ptr, domain_name, 254);
            offset += 2;
        }
        // if its an encoded_domain_name
        else {
            // domain_ptr is the first byte
            domain_ptr = response + offset;
            decode_hostname(domain_ptr, domain_name, 254);
            offset += strlen(domain_ptr) + 1;
        }

        Resource_Record record;
        strcpy(record.name, domain_name);
        // get answer type : 2B
        record.type = htons(*(uint16_t*)(response + offset));
        offset += 2;
        // get answer class : 2B
        record.class = htons(*(uint16_t*)(response + offset));
        offset += 2;
        // get time-to-live : 4B
        record.ttl = htons(*(uint32_t*)(response + offset));
        offset += 4;
        // get answer length : 2B
        record.rdlen = htons(*(uint16_t*)(response + offset));
        offset += 2;

        record.answer = malloc(record.rdlen);
        for (int i = 0; i < record.rdlen; i++){
            record.answer[i] = *(response + offset);
            offset++;
        }

        record.answer[record.rdlen] = '\0';

        display_dns_record(record);

        free(record.answer);
    }
}


int main(int argc, char *argv[]){

    if (argc != 2) {
        printf("Usage: ./resolve <domain_name>\n");
        return 1;
    }
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0){
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    srand(time(NULL));

    uint8_t *request = calloc(1, 512);
    uint16_t id = 0;
    int req_len = build_dns_query(argv[1], request, 512, &id);
    send_dns_query(sock, DNS_SERVER, request, req_len);

    uint8_t *response = calloc(1, 512);
    int resposne_len = recv_dns_response(sock, DNS_SERVER, response, 512);
    parse_dns_response(response, 512, id);

    return 0;
}