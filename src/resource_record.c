#include "resource_record.h"
#include <string.h>
#include <arpa/inet.h>
#include "utils.h"
#include <stdio.h>

DnsResourceRecord build_rr(const char owner[], enum Type type, enum Class class, uint32_t ttl, uint16_t rdlen, const char rdata[]) {
    DnsResourceRecord rr;
    rr.owner = strdup(owner);
    rr.type = (uint16_t)type;
    rr.class = (uint16_t)class;
    rr.ttl = ttl;
    rr.rdlen = rdlen;
    rr.rdata = malloc(rdlen);
    memcpy(rr.rdata, rdata, rdlen);
    return rr;
}

size_t sizeof_rr(DnsResourceRecord rr) {
    size_t size = 0;
    size += strlen(rr.owner) + 1;
    size += 2 + 2 + 4 + 2;
    size += rr.rdlen;
    return size;
}

int memcpy_rr(uint8_t buffer[],DnsResourceRecord rr) {
    size_t owner_size = strlen(rr.owner) + 1;
    memcpy(buffer, &rr.owner, owner_size);
    memcpy(buffer + owner_size, &rr.type, 2);
    memcpy(buffer + owner_size + 2, &rr.class, 2);
    memcpy(buffer + owner_size + 2 + 2, &rr.ttl, 4);
    memcpy(buffer + owner_size + 2 + 2 + 4, &rr.rdlen, 2);
    memcpy(buffer + owner_size + 2 + 2 + 4 + 2, &rr.rdata, rr.rdlen);
    return 0;
}

int cpy_rr(DnsResourceRecord *dest, const DnsResourceRecord src) {
    dest->owner = strdup(src.owner);
    dest->type = src.type;
    dest->class = src.class;
    dest->ttl = src.ttl;
    dest->rdlen = src.rdlen;
    dest->rdata = malloc(src.rdlen);
    memcpy(dest->rdata, src.rdata, src.rdlen);
    return 0;
}

DnsResourceRecord hton_rr(DnsResourceRecord rr) {
    rr.type = htons(rr.type);
    rr.class = htons(rr.class);
    rr.ttl = htonl(rr.ttl);
    rr.rdlen = htons(rr.rdlen);
    return rr;
}

DnsResourceRecord ntoh_rr(DnsResourceRecord rr) {
    rr.type = ntohs(rr.type);
    rr.class = ntohs(rr.class);
    rr.ttl = ntohl(rr.ttl);
    rr.rdlen = ntohs(rr.rdlen);
    return rr;
}

DnsResourceRecord* parse_rrs(const uint8_t buffer[], size_t *buffer_offset, uint16_t rr_count) {
    DnsResourceRecord *rrs = malloc(rr_count * sizeof(DnsResourceRecord));
    
    for (int i = 0; i < ntohs(rr_count); i++) {
        rrs[i].owner = parse_name(buffer, buffer_offset);

        memcpy(&rrs[i].type, buffer + *buffer_offset, 2);
        *buffer_offset += 2;
        
        memcpy(&rrs[i].class, buffer + *buffer_offset, 2);
        *buffer_offset += 2;

        memcpy(&rrs[i].ttl, buffer + *buffer_offset, 4);
        *buffer_offset += 4;

        memcpy(&rrs[i].rdlen, buffer + *buffer_offset, 2);
        *buffer_offset += 2;

        if (ntohs(rrs[i].type) == CNAME || ntohs(rrs[i].type) == NS || ntohs(rrs[i].type) == PTR) {
            rrs[i].rdata = (uint8_t *)parse_name(buffer, buffer_offset);
        } else if (ntohs(rrs[i].type) == MX){
            rrs[i].rdata = malloc(2);
            memcpy(rrs[i].rdata, buffer + *buffer_offset, 2);
            *buffer_offset += 2;
            
            char *mail_name = parse_name(buffer, buffer_offset);
            rrs[i].rdata = realloc(rrs[i].rdata, 2 + strlen(mail_name)+1);
            memcpy(rrs[i].rdata+2, mail_name, strlen(mail_name)+1);
            free(mail_name);
        } else {
            rrs[i].rdata = malloc(ntohs(rrs[i].rdlen));
            memcpy(rrs[i].rdata, buffer + *buffer_offset, ntohs(rrs[i].rdlen));
            *buffer_offset += htons(rrs[i].rdlen);
        }
    }

    return rrs;
}

void free_rrs(DnsResourceRecord resource_records[], uint16_t count) {
    for (int i = 0; i < count; i++) {
        free(resource_records[i].owner);
        free(resource_records[i].rdata);
    }
    free(resource_records);
}
