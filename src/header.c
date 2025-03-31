#include "header.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

DnsHeader build_header(uint16_t id, uint16_t flags, uint16_t qd_count, uint16_t an_count, uint16_t ns_count, uint16_t ar_count) {
    DnsHeader header;
    header.id = id;
    header.flags = flags;
    header.qd_count = qd_count;
    header.an_count = an_count;
    header.ns_count = ns_count;
    header.ar_count = ar_count;
    return header;
}

size_t sizeof_header(DnsHeader header) {
    return sizeof(header);
}

int memcpy_header(uint8_t *buffer, DnsHeader header) {
    memcpy(buffer, &header.id, 2);
    memcpy(buffer + 2, &header.flags, 2);
    memcpy(buffer + 4, &header.qd_count, 2);
    memcpy(buffer + 6, &header.an_count, 2);
    memcpy(buffer + 8, &header.ns_count, 2);
    memcpy(buffer + 10, &header.ar_count, 2);
    return 0;
}

DnsHeader hton_header(DnsHeader header) {
    header.id = htons(header.id);
    header.flags = htons(header.flags);
    header.qd_count = htons(header.qd_count);
    header.an_count = htons(header.an_count);
    header.ns_count = htons(header.ns_count);
    header.ar_count = htons(header.ar_count);
    return header;
}

DnsHeader ntoh_header(DnsHeader header) {
    header.id = ntohs(header.id);
    header.flags = ntohs(header.flags);
    header.an_count = ntohs(header.an_count);
    header.qd_count = ntohs(header.qd_count);
    header.ns_count = ntohs(header.ns_count);
    header.ar_count = ntohs(header.ar_count);
    return header;
}

DnsHeader parse_header(const uint8_t buffer[], size_t *buffer_offset) {
    DnsHeader header = *(DnsHeader*)buffer;
    *buffer_offset += sizeof(DnsHeader);
    return header;
}
