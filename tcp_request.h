#ifndef TCP_REQUEST_H
#define TCP_REQUEST_H

#include "dnscrypt.h"

#define DNS_MAX_PACKET_SIZE_TCP (65535U + 2U)

#ifndef TCP_REQUEST_BACKLOG
# define TCP_REQUEST_BACKLOG 128
#endif

struct context;
struct cert_;

typedef struct TCPRequestStatus_ {
    bool has_dns_query_len:1;
    bool has_dns_reply_len:1;
    bool is_in_queue:1;
    bool is_dying: