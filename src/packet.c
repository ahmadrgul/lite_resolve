#include "packet.h"
#include "stdlib.h"
#include <arpa/inet.h>

DnsPacket build_packet(DnsHeader header, const DnsQuestion questions[], const DnsResourceRecord answers[], const DnsResourceRecord authorities[], const DnsResourceRecord additionals[]) {
    DnsPacket packet;
    packet.header = header;

    packet.questions = malloc(header.qd_count * sizeof(DnsQuestion));
    for (int i = 0; i < packet.header.qd_count; i++) {
        cpy_question(&packet.questions[i], questions[i]);
    }

    if (answers != NULL) {
        packet.answers = malloc(header.an_count * sizeof(DnsResourceRecord));
        for (int i = 0; i < header.an_count; i++) {
            cpy_rr(&packet.answers[i], answers[i]);
        }
    } else {
        packet.answers = NULL;
    }

    if (authorities != NULL) {
        packet.authorities = malloc(header.ns_count * sizeof(DnsResourceRecord));
        for (int i = 0; i < header.ns_count; i++) {
            cpy_rr(&packet.authorities[i], authorities[i]);
        }
    } else {
        packet.authorities = NULL;
    }

    if (additionals != NULL) {
        packet.additionals = malloc(header.ar_count * sizeof(DnsResourceRecord));
        for (int i = 0; i < header.ar_count; i++) {
            cpy_rr(&packet.additionals[i], additionals[i]);
        }
    } else {
        packet.additionals = NULL;
    }

    return packet;
}

size_t sizeof_packet(DnsPacket packet) {
    size_t size = 0;

    size += sizeof_header(packet.header);
    for (int i = 0; i < packet.header.qd_count; i++) {
        size += sizeof_question(packet.questions[i]);
    }
    for (int i = 0; i < packet.header.an_count; i++) {
        size += sizeof_rr(packet.answers[i]);
    }
    for (int i = 0; i < packet.header.ns_count; i++) {
        size += sizeof_rr(packet.authorities[i]);
    }
    for (int i = 0; i < packet.header.ar_count; i++) {
        size += sizeof_rr(packet.additionals[i]);
    }
    return size;
}

int memcpy_packet(uint8_t *buffer, DnsPacket packet) {
    size_t offset = 0;
    memcpy_header(buffer, packet.header);
    offset += sizeof_header(packet.header);
    for (int i = 0; i < ntohs(packet.header.qd_count); i++) {
        memcpy_question(buffer + offset, packet.questions[i]);
        offset += sizeof_question(packet.questions[i]);
    }
    return 0;
}


// this function is not yet implemented completely
int cpy_packet(DnsPacket *dest, DnsPacket src) {
    dest->header = src.header;
    for (int i = 0; i < src.header.qd_count; i++) {
        dest->questions = realloc(dest->questions, sizeof(DnsQuestion) * (i+1));
        cpy_question(dest->questions + i, src.questions[i]);
    }
    for (int i = 0; i < src.header.an_count; i++) {
        dest->answers = realloc(dest->answers, sizeof(DnsResourceRecord) * (i+1));
        cpy_rr(dest->answers + i, src.answers[i]);
    }
    for (int i = 0; i < src.header.ns_count; i++) {
        dest->authorities = realloc(dest->authorities, sizeof(DnsResourceRecord) * (i+1));
        cpy_rr(dest->authorities + i, src.authorities[i]);
    }
    for (int i = 0; i < src.header.ar_count; i++) {
        dest->additionals = realloc(dest->additionals, sizeof(DnsResourceRecord) * (i+1));
        cpy_rr(dest->additionals + i, src.additionals[i]);
    }
    return 1;
}

DnsPacket hton_packet(DnsPacket packet) {
    for (int i = 0; i < packet.header.qd_count; i++) {
        packet.questions[i] = hton_question(packet.questions[i]);
    }
    for (int i = 0; i < packet.header.an_count; i++) {
        packet.answers[i] = hton_rr(packet.answers[i]);
    }
    for (int i = 0; i < packet.header.ns_count; i++) {
        packet.authorities[i] = hton_rr(packet.authorities[i]);
    }
    for (int i = 0; i < packet.header.ar_count; i++) {
        packet.additionals[i] = hton_rr(packet.additionals[i]);
    }
    packet.header = hton_header(packet.header);
    return packet;
}

DnsPacket ntoh_packet(DnsPacket packet) {
    packet.header = ntoh_header(packet.header);
    for (int i = 0; i < packet.header.qd_count; i++) {
        packet.questions[i] = ntoh_question(packet.questions[i]);
    }
    for (int i = 0; i < packet.header.an_count; i++) {
        packet.answers[i] = ntoh_rr(packet.answers[i]);
    }
    for (int i = 0; i < packet.header.ns_count; i++) {
        packet.authorities[i] = ntoh_rr(packet.authorities[i]);
    }
    for (int i = 0; i < packet.header.ar_count; i++) {
        packet.additionals[i] = ntoh_rr(packet.additionals[i]);
    }
    return packet;
}

DnsPacket parse_packet(const uint8_t buffer[]) {
    size_t buffer_offset = 0;

    DnsPacket packet;
    packet.header = parse_header(buffer, &buffer_offset);
    packet.questions = parse_questions(buffer, &buffer_offset, packet.header.qd_count);
    packet.answers = parse_rrs(buffer, &buffer_offset, packet.header.an_count);
    packet.authorities = parse_rrs(buffer, &buffer_offset, packet.header.ns_count);
    packet.additionals = parse_rrs(buffer, &buffer_offset, packet.header.ar_count);

    return packet;
}

void free_packet(DnsPacket packet) {
    free_questions(packet.questions, packet.header.qd_count);
    free_rrs(packet.answers, packet.header.an_count);
    free_rrs(packet.authorities, packet.header.ns_count);
    free_rrs(packet.additionals, packet.header.ar_count);
}
