#ifndef UDP_REQUEST_H
#define UDP_REQUEST_H

#include "dnscrypt.h"

struct context;
struct cert_;

typedef struct UDPRequestStatus_ {
    bool is_dying:1;
    bool is_in_queue:1;
} UDPRequestStatus;

typedef struct UDPRequest_ {
    RB_ENTRY(UDPRequest_) queue;
    struct context *context;
    struct event *sendto_retry_timer;
    struct even