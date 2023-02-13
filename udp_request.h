#ifndef UDP_REQUEST_H
#define UDP_REQUEST_H

#include "dnscrypt.h"

struct context;
struct cert_;

typedef struct UDPRequestStatus_ {
    bool is_dying: