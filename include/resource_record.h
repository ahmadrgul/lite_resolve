#ifndef RESOURCE_RECORD
#define RESOURCE_RECORD

#include <stdint.h>
#include <stdlib.h>
#include "common.h"

typedef struct {
    char *owner;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlen;
    uint8_t *rdata;
} DnsResourceRecord;

DnsResourceRecord build_rr(const char owner[], const enum Type type, const enum Class class, const uint32_t ttl, const uint16_t rdlen, const char rdata[]);
size_t sizeof_rr(DnsResourceRecord rr);
int memcpy_rr(uint8_t buffer[], DnsResourceRecord rr);
int cpy_rr(DnsResourceRecord *dest, DnsResourceRecord src);
DnsResourceRecord hton_rr(DnsResourceRecord rr);
DnsResourceRecord ntoh_rr(DnsResourceRecord rr);
DnsResourceRecord* parse_rrs(const uint8_t buffer[], size_t *buffer_offset, uint16_t rr_count);
void free_rrs(DnsResourceRecord resource_records[], uint16_t count);

#endif
