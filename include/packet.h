#ifndef PACKET
#define PACKET

#include <stdint.h>
#include "header.h"
#include "question.h"
#include "resource_record.h"

typedef struct {
    DnsHeader header;
    DnsQuestion *questions;
    DnsResourceRecord *answers;
    DnsResourceRecord *authorities;
    DnsResourceRecord *additionals;
} DnsPacket;

DnsPacket build_packet(DnsHeader header, const DnsQuestion questions[], const DnsResourceRecord answers[], const DnsResourceRecord authorities[], const DnsResourceRecord additionals[]);
size_t sizeof_packet(DnsPacket packet);
int memcpy_packet(uint8_t *buffer, DnsPacket packet);
int cpy_packet(DnsPacket *dest, DnsPacket src);
DnsPacket hton_packet(DnsPacket packet);
DnsPacket ntoh_packet(DnsPacket packet);
DnsPacket parse_packet(const uint8_t buffer[]);
void free_packet(DnsPacket packet);

#endif