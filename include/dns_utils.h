#ifndef DNS_UTILS
#define DNS_UTILS
#include<stdint.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<unistd.h>
#include<time.h>


#define DNS_PORT 53
#define DNS_SERVER "8.8.8.8"
#define TYPES_COUNT 28

enum Type { UNKNOWN=0, A=1, NS=2, CNAME=5, SOA=6, PTR=12, MX=15, TXT=16, AAAA=28 };
enum Class { IN=1, CS, CH, HS };

typedef struct {
    enum Type type;
    char *query;
} UserQuery;

typedef struct {
    char ***answers;
    uint8_t *count;
} DNSAnswerSet;

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
} DNS_header;

typedef struct {
    uint16_t q_type;
    uint16_t q_class;
} DNS_question;

typedef struct {
    char name[255];
    enum Type type;
    enum Class class;
    uint32_t ttl;
    uint16_t rdlen;
    uint8_t *answer;
} Resource_Record;


const char* typeToString(enum Type type);
enum Type stringToType(const char *str);
UserQuery parseUserQuery(int c, char *v[]);

DNSAnswerSet* build_ans_set();
void append_ans_set(DNSAnswerSet *set, int type, const char *answer);
void free_ans_set(DNSAnswerSet *set);

char* encode_domain(const char *domain_name);

char* parse_ipv4_data(uint8_t *rdata);
char* parse_ipv6_data(uint8_t *rdata);
char* parse_domain_rdata(int offset,const uint8_t *response_buffer);
char* format_domain_name(char **labels);

int decode_domain(int offset, const uint8_t *begin, char **domain_name);
Resource_Record parse_dns_record(const uint8_t *response_buffer, int *offset);
void process_rr(uint16_t count, uint8_t section, const uint8_t *response_buffer, int *offset, enum Type qtype, DNSAnswerSet *res);

void handle_rerror(uint8_t code);

#endif