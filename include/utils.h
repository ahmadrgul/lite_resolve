#ifndef UTILS
#define UTILS

#include <stdint.h>
#include <stdlib.h>
#include "common.h"
#include "resource_record.h"

#define DNS_PORT 53
#define DNS_SERVER "8.8.8.8"
#define TYPES_COUNT 28


typedef struct {
    char *query;
    enum Type type;
} UserQuery;

typedef struct {
    char *query;
    enum Type type;
    void* answer;
} UserResponse;

char* type_to_string(enum Type type);
enum Type string_to_type(const char *str);
UserQuery parse_user_query(int c, char *v[]);
UserResponse* build_user_responses(const DnsResourceRecord answers[], uint16_t an_count);
void free_user_responses(UserResponse responses[], uint16_t count);
char* encode_name(const char *decoded);
char* decode_name(const char *encoded);
char* parse_name(const uint8_t buffer[], size_t *buffer_offset);
char* parse_rdata(const uint8_t *data, enum Type type);

void handle_rerror(uint8_t code);

#endif
