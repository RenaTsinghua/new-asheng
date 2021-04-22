
#ifndef DNSCRYPT_H
#define DNSCRYPT_H

#include "compat.h"
#include "tree.h"
#include "debug.h"
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <sodium.h>

#if SODIUM_LIBRARY_VERSION_MAJOR < 7
# define sodium_allocarray(C, S) calloc(C, S)
# define sodium_malloc(S) malloc(S)
# define sodium_free(P) free(P)
#endif

#define DNS_QUERY_TIMEOUT 10

#define DNS_MAX_PACKET_SIZE_UDP_RECV (65536U - 20U - 8U)
#define DNS_MAX_PACKET_SIZE_UDP_SEND 512U

#if DNS_MAX_PACKET_SIZE_UDP_RECV > DNS_MAX_PACKET_SIZE_UDP_SEND
# define DNS_MAX_PACKET_SIZE_UDP DNS_MAX_PACKET_SIZE_UDP_RECV
#else
# define DNS_MAX_PACKET_SIZE_UDP DNS_MAX_PACKET_SIZE_UDP_SEND
#endif

#ifndef DNS_DEFAULT_STANDARD_DNS_PORT
# define DNS_DEFAULT_STANDARD_DNS_PORT "53"