#include "dns_utils.h"
#include <ctype.h>

const char* typeToString(enum Type type) {
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

enum Type stringToType(const char *str) {
    size_t len = strlen(str);
    char upperStr[len+1];

    for (size_t i = 0; i < len; i++) {
        upperStr[i] = toupper(str[i]);
    }
    upperStr[len] = '\0';

    if (strcmp(upperStr, "A") == 0) return A;
    if (strcmp(upperStr, "AAAA") == 0) return AAAA;
    if (strcmp(upperStr, "CNAME") == 0) return CNAME;
    if (strcmp(upperStr, "MX") == 0) return MX;
    if (strcmp(upperStr, "NS") == 0) return NS;
    if (strcmp(upperStr, "PTR") == 0) return PTR;
    if (strcmp(upperStr, "SOA") == 0) return SOA;
    if (strcmp(upperStr, "TXT") == 0) return TXT;
    return UNKNOWN;
}

UserQuery parseUserQuery(int c, char *v[]) {
    UserQuery uq;
    uq.type = c == 2 ? A : stringToType(v[1]);
    uq.query = c == 2 ? v[1] : v[2];
    return uq;
}

DNSAnswerSet* build_ans_set() {
    DNSAnswerSet *set = malloc(sizeof(DNSAnswerSet));
    set->answers = calloc(TYPES_COUNT, sizeof(char**));
    set->count = calloc(TYPES_COUNT, sizeof(uint16_t));
    return set;
}

void append_ans_set(DNSAnswerSet *set, int type, const char *answer) {
    type -= 1;
    set->answers[type] = realloc(set->answers[type], (set->count[type] + 1) * sizeof(char *));
    set->answers[type][set->count[type]] = malloc(strlen(answer) + 1);
    strcpy(set->answers[type][set->count[type]], answer);
    set->count[type]++;
}

void free_ans_set(DNSAnswerSet *set) {
    for (int type = TYPES_COUNT-1; type >= 0; type--) {
        int i = set->count[type]-1;
        while (i >= 0) {
            free(set->answers[type][i]);
            --i;
        }
        free(set->answers[type]);
    }
    free(set->count);
    free(set);
}

char* encode_domain(const char *domain_name){
    int len = strlen(domain_name);
    char* encoded = malloc(len + 2);
    int encoded_index = 0;

    // traverse the whole hostname character by character
    for (int i = 0; i < len; i++){

        if (domain_name[i] != '.'){
            // if character is not a dot, copy the character as it is
            // copy the entire hostname into encoded_hostname, excepting the dots
            encoded[++encoded_index] = domain_name[i];
            // encoded_index is one greater than hostname index, since encoded_hostname contain label at start
        } else {
            // if a dot is encountered, it means a label has ended
            
            // index (in hostname) of 'last character of last label copied'
            int j = i - 1;
            // length of the label last copied
            int label_len = 0;

            // calculate the length of last copied label
            while (j >= 0 && domain_name[j] != '.') {
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
            while (i >= 0 && domain_name[i] != '.') {
                ++label_len;
                --i;
            }
            encoded[encoded_index - label_len] = (size_t)label_len;
            encoded_index++;
            break;
        }
    }
    
    // put null terminator at the end of encoded_hostname
    encoded[encoded_index] = '\0';
    return encoded;
}

char* parse_ipv6_data(uint8_t *rdata) {
    static char ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, rdata, ip, sizeof(ip));
    return ip;
}

char* parse_ipv4_data(uint8_t *rdata) {
    static char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, rdata, ip, sizeof(ip));
    return ip;
}

char* parse_domain_rdata(int offset, const uint8_t *response_buffer) {
    char **labels = malloc(127 * sizeof(char *));
    decode_domain(offset, response_buffer, labels);
    char *cname = format_domain_name(labels);
    free(labels);
    return cname;
}

char* format_domain_name(char **labels) {
    char *domain = calloc(255, sizeof(char));
    for (int i = 0; labels[i] != NULL; i++) {
        strcat(domain, labels[i]);
        strcat(domain, ".");
        free(labels[i]);
    }
    // remove extra dot
    domain[strlen(domain)-1] = '\0';
    return domain;
}

int decode_domain(int offset, const uint8_t *begin, char **domain_name) {
    int domain_index = 0;
    int len = 0;
    uint8_t ptr = 0;

    while (*(begin + offset) != '\0') {
        if (!ptr) ++len;
        
        // if first two bits of any octet are 11, its pointer
        if ((*(begin + offset) & 0b11 << 6) == 0b11 << 6) {
            offset = (ntohs(*(uint16_t*)(begin + offset)) & 0x3FFF);
            ptr = 1; // yes
            continue;
        }
        
        size_t label_len = *(begin + offset++);
        *(domain_name + domain_index) = malloc(63);

        int j = 0;
        while ((size_t)j < label_len) {
            domain_name[domain_index][j++] = *(begin + offset++);
            if (!ptr) ++len;
        }
        domain_name[domain_index][j] = '\0';
        domain_index++;
    }

    domain_name[domain_index] = NULL;

    return len;
}

Resource_Record parse_dns_record(const uint8_t *response_buffer, int *offset) {
    Resource_Record record;
    char **domain_labels = malloc(127 * sizeof(char *));
    *offset += decode_domain(*offset, response_buffer, domain_labels) + 1;

    strcpy(record.name, format_domain_name(domain_labels));
    record.type = ntohs(*(uint16_t*)(response_buffer + *offset));
    *offset += 2;
    record.class = ntohs(*(uint16_t*)(response_buffer + *offset));
    *offset += 2;
    record.ttl = ntohl(*(uint32_t*)(response_buffer + *offset));
    *offset += 4;
    record.rdlen = ntohs(*(uint16_t*)(response_buffer + *offset));
    *offset += 2;

    record.answer = malloc(record.rdlen);
    memcpy(record.answer, response_buffer + *offset, record.rdlen);
    record.answer[record.rdlen] = '\0';

    return record;
}

void process_rr(uint16_t count, uint8_t section, const uint8_t *response_buffer, int *offset, enum Type qtype, DNSAnswerSet *res) {
    for (int i = 0; i < count; i++){
        Resource_Record record = parse_dns_record(response_buffer, offset);
        char *answer = NULL;

        if (section == 1){
            if (qtype == A) {
                answer = record.type == A ? parse_ipv4_data(record.answer) : parse_domain_rdata(*offset, response_buffer);
            } else if (qtype == AAAA) {
                answer = record.type == AAAA ? parse_ipv6_data(record.answer) : parse_domain_rdata(*offset, response_buffer);
            } else if (qtype == NS) {
                answer = parse_domain_rdata(*offset, response_buffer);
            }
        }
        if (answer != NULL) append_ans_set(res, record.type, answer);

        *offset += record.rdlen;
        if (record.answer)
            free(record.answer);
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