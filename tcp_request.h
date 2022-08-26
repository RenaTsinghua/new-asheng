#ifndef TCP_REQUEST_H
#define TCP_REQUEST_H

#include "dnscrypt.h"

#define DNS_MAX_PACKET_SIZE_TCP (65535U + 2U)

#ifndef TCP_REQUEST_BACKLOG
# define TCP_