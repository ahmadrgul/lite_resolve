#ifndef QUESTION
#define QUESTION

#include "utils.h"
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    char *name;
    uint16_t type;
    uint16_t class;
} DnsQuestion;

DnsQuestion build_question(const char query[], enum Type type, enum Class class);
size_t sizeof_question(DnsQuestion question);
int memcpy_question(uint8_t buffer[], DnsQuestion question);
int cpy_question(DnsQuestion *dest, DnsQuestion src);
DnsQuestion hton_question(DnsQuestion question);
DnsQuestion ntoh_question(DnsQuestion question);
DnsQuestion* parse_questions(const uint8_t buffer[], size_t *buffer_offset, uint16_t qd_count);
void free_questions(DnsQuestion questions[], uint16_t qd_count);

#endif