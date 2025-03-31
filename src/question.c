#include "question.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

DnsQuestion build_question(const char query[], enum Type type, enum Class class) {
    DnsQuestion q;
    if (type == PTR) {
        int addr[4];
        sscanf(query, "%d.%d.%d.%d", &addr[3], &addr[2], &addr[1], &addr[0]);
        char *ptr_query = malloc(strlen(query) + 14);
        sprintf(ptr_query, "%d.%d.%d.%d.in-addr.arpa", addr[0], addr[1], addr[2], addr[3]);
        q.name = encode_name(ptr_query);
        free(ptr_query);
    } else {
        q.name = encode_name(query);
    }

    q.type = (uint16_t)type;
    q.class = (uint16_t)class;
    return q;
}

size_t sizeof_question(DnsQuestion question) {
    size_t size = 0;
    size += strlen(question.name) + 1;
    size += 4;
    return size;
}

int memcpy_question(uint8_t buffer[], DnsQuestion question) {
    size_t domain_size = strlen(question.name) + 1;
    memcpy(buffer, question.name, domain_size);
    memcpy(buffer + domain_size, &question.type, 2);
    memcpy(buffer + domain_size + 2, &question.class, 2);
    return 0;
}

int cpy_question(DnsQuestion *dest, DnsQuestion src) {
    size_t doman_size = strlen(src.name) + 1;
    dest->name = malloc(doman_size);
    memcpy(dest->name, src.name, doman_size);
    dest->type = src.type;
    dest->class = src.class;
    return 0;
}

DnsQuestion hton_question(DnsQuestion question) {
    question.type = htons(question.type);
    question.class = htons(question.class);
    return question;
}

DnsQuestion ntoh_question(DnsQuestion question) {
    question.type = ntohs(question.type);
    question.class = ntohs(question.class);
    return question;
}

DnsQuestion* parse_questions(const uint8_t buffer[], size_t *buffer_offset, uint16_t qd_count) {
    DnsQuestion *questions = malloc(qd_count * sizeof(DnsQuestion));
    for (int i = 0; i < ntohs(qd_count); i++) {
        questions[i].name = parse_name(buffer, buffer_offset);

        memcpy(&questions[i].type, buffer + *buffer_offset, 2);
        *buffer_offset += 2;
    
        memcpy(&questions[i].class, buffer + *buffer_offset, 2);
        *buffer_offset += 2;
        
    }

    return questions;
}

void free_questions(DnsQuestion questions[], uint16_t qd_count) {
    for (int i = 0; i < qd_count; i++) {
        free(questions[i].name);
    }
    free(questions);
}
