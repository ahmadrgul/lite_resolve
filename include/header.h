#ifndef HEADER
#define HEADER

#include <stdint.h>
#include <stdlib.h>

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
} DnsHeader;

DnsHeader build_header(uint16_t id, uint16_t flags, uint16_t qd_count, uint16_t an_count, uint16_t ns_count, uint16_t ar_count);
size_t sizeof_header(DnsHeader header);
int memcpy_header(uint8_t *buffer, DnsHeader header);
DnsHeader hton_header(DnsHeader header);
DnsHeader ntoh_header(DnsHeader header);
DnsHeader parse_header(const uint8_t buffer[], size_t *buffer_offset);

#endif