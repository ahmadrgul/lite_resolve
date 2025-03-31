#include "utils.h"
#include "resource_record.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>


typedef struct {
    uint16_t preference;
    char *name;
} MxRdata;

char* type_to_string(enum Type type) {
    switch (type) {
        case A: return "IPv4";
        case NS: return "NS";
        case CNAME: return "CNAME";
        case SOA: return "SOA";
        case PTR: return "PTR";
        case MX: return "MX";
        case TXT: return "TXT";
        case AAAA: return "IPv6";
        default: return "Unknown";
    }
}

enum Type string_to_type(const char *str) {
    size_t len = strlen(str);
    char upper_str[len+1];

    for (size_t i = 0; i < len; i++) {
        upper_str[i] = toupper(str[i]);
    }
    upper_str[len] = '\0';

    if (strcmp(upper_str, "A") == 0) return A;
    if (strcmp(upper_str, "AAAA") == 0) return AAAA;
    if (strcmp(upper_str, "CNAME") == 0) return CNAME;
    if (strcmp(upper_str, "MX") == 0) return MX;
    if (strcmp(upper_str, "NS") == 0) return NS;
    if (strcmp(upper_str, "PTR") == 0) return PTR;
    if (strcmp(upper_str, "SOA") == 0) return SOA;
    if (strcmp(upper_str, "TXT") == 0) return TXT;
    return UNKNOWN;
}

UserQuery parse_user_query(int c, char *v[]) {
    UserQuery uq;
    uq.type = c == 2 ? A : string_to_type(v[1]);
    uq.query = c == 2 ? v[1] : v[2];
    if (uq.type == SOA || uq.type == SOA) {
        fprintf(stderr, "Unable to resolve %s records\n", type_to_string(uq.type));
        exit(EXIT_FAILURE);
    }
    return uq;
}

UserResponse* build_user_responses(const DnsResourceRecord answers[], uint16_t an_count) {
    UserResponse *responses = malloc(an_count * sizeof(UserResponse));

    for (int i = 0; i < an_count; i++) {
        responses[i].query = decode_name(answers[i].owner);
        responses[i].type = answers[i].type;
        responses[i].answer = parse_rdata(answers[i].rdata, responses[i].type);
    }

    return responses;
}

void free_user_responses(UserResponse responses[], uint16_t count) {
    for(int i = 0; i < count; i++) {
        free(responses[i].query);
        free(responses[i].answer);
    }
    free(responses);
}

char* encode_name(const char *decoded) {
    char *encoded = malloc(256);
    uint8_t decoded_index = 0;
    uint8_t encoded_index = 1;
    uint8_t size_position = 0;
    size_t label_size = 0;

    while(decoded[decoded_index] != '\0') {
        if (decoded[decoded_index] != '.') {
            encoded[encoded_index++] = decoded[decoded_index++];
            label_size++;
        } else {
            encoded[size_position] = label_size;
            label_size = 0;
            size_position = encoded_index++;
            decoded_index++;
        }
    }

    encoded[size_position] = label_size;
    encoded[encoded_index] = '\0';

    return encoded;
}

char* decode_name(const char *encoded) {
    char *decoded = malloc(256);

    uint8_t encoded_index = 0;
    uint8_t decoded_index = 0;

    while (encoded[encoded_index] != '\0') {
        size_t label_size = encoded[encoded_index++];
        uint8_t j = 0;
        while (j < label_size) {
            decoded[decoded_index++] = encoded[encoded_index++];
            j++;
        }
        decoded[decoded_index++] = '.';
    }

    decoded[decoded_index-1] = '\0';
    return decoded;
}

char* parse_name(const uint8_t buffer[], size_t *buffer_offset) {
    char *name = malloc(256);
    uint8_t name_index = 0;
    uint8_t ptr = 0; // false
    size_t offset = *buffer_offset;

    while (buffer[offset] != '\0') {

        if ((buffer[offset] & 0xC0) == 0xC0) {
            offset = ntohs(*(uint16_t*)(buffer + offset)) & (0x3FFF);
            if (!ptr) *(buffer_offset) += 2;
            ptr = 1; // true
            continue;
        }
        
        name[name_index++] = *(buffer + offset++);
        if (!ptr) (*buffer_offset)++;
    }

    name[name_index] = '\0';

    if (!ptr) (*buffer_offset)++;

    return name;
}

char* parse_rdata(const uint8_t *data, enum Type type) {
    if (type == A) {
        char *ip4 = malloc(INET_ADDRSTRLEN);
        inet_ntop(AF_INET, data, ip4, 16);
        return ip4;
    } else if (type == AAAA) {
        char *ip6 = malloc(INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, data, ip6, 46);
        return ip6;
    } else if (type == CNAME || type == NS || type == PTR) {
        char *name = decode_name((char*)data);
        return name;
    } else if (type == MX) {
        MxRdata mxdata;
        memcpy(&mxdata.preference, data, 2);
        mxdata.name = decode_name((char*)(data + 2));
        return mxdata.name;
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

    printf("%s...\n", err);
    exit(code);
}
