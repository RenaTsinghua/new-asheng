
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
#endif
#ifndef DNS_DEFAULT_LOCAL_PORT
# define DNS_DEFAULT_LOCAL_PORT DNS_DEFAULT_STANDARD_DNS_PORT
#endif
#ifndef DNS_DEFAULT_RESOLVER_PORT
# define DNS_DEFAULT_RESOLVER_PORT "443"
#endif

#define DNS_HEADER_SIZE  12U
#define DNS_FLAGS_TC      2U
#define DNS_FLAGS_QR    128U
#define DNS_FLAGS2_RA   128U

#define DNS_CLASS_IN      1U
#define DNS_TYPE_TXT     16U
#define DNS_TYPE_OPT     41U

#define DNS_OFFSET_QUESTION DNS_HEADER_SIZE
#define DNS_OFFSET_FLAGS    2U
#define DNS_OFFSET_FLAGS2   3U
#define DNS_OFFSET_QDCOUNT  4U
#define DNS_OFFSET_ANCOUNT  6U
#define DNS_OFFSET_NSCOUNT  8U
#define DNS_OFFSET_ARCOUNT 10U

#define DNS_OFFSET_EDNS_TYPE         0U
#define DNS_OFFSET_EDNS_PAYLOAD_SIZE 2U

#define DNS_DEFAULT_EDNS_PAYLOAD_SIZE 1252U

#define DNSCRYPT_MAGIC_HEADER_LEN 8U
#define DNSCRYPT_MAGIC_RESPONSE  "r6fnvWj8"

#ifndef DNSCRYPT_MAX_PADDING
# define DNSCRYPT_MAX_PADDING 256U
#endif
#ifndef DNSCRYPT_BLOCK_SIZE
# define DNSCRYPT_BLOCK_SIZE 64U
#endif
#ifndef DNSCRYPT_MIN_PAD_LEN
# define DNSCRYPT_MIN_PAD_LEN 8U
#endif

#define crypto_box_HALF_NONCEBYTES (crypto_box_NONCEBYTES / 2U)

#include "edns.h"
#include "udp_request.h"
#include "tcp_request.h"
#include "rfc1035.h"
#include "logger.h"
#include "safe_rw.h"
#include "cert.h"

#define DNSCRYPT_QUERY_HEADER_SIZE \
    (DNSCRYPT_MAGIC_HEADER_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES + crypto_box_MACBYTES)
#define DNSCRYPT_RESPONSE_HEADER_SIZE \
    (DNSCRYPT_MAGIC_HEADER_LEN + crypto_box_NONCEBYTES + crypto_box_MACBYTES)

#define DNSCRYPT_REPLY_HEADER_SIZE \
    (DNSCRYPT_MAGIC_HEADER_LEN + crypto_box_HALF_NONCEBYTES * 2 + crypto_box_MACBYTES)

#define XSALSA20_CERT(cert) (cert->es_version[0] == 0 && \
    cert->es_version[1] == 1)
#define XCHACHA20_CERT(cert) (cert->es_version[0] == 0 && \
    cert->es_version[1] == 2)

typedef struct KeyPair_ {
    uint8_t crypt_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t crypt_secretkey[crypto_box_SECRETKEYBYTES];
} KeyPair;

typedef struct cert_ {
    uint8_t magic_query[DNSCRYPT_MAGIC_HEADER_LEN];
    uint8_t es_version[2];
    KeyPair *keypair;
} dnsccert;

struct context {
    struct sockaddr_storage local_sockaddr;
    struct sockaddr_storage resolver_sockaddr;
    struct sockaddr_storage outgoing_sockaddr;
    ev_socklen_t local_sockaddr_len;
    ev_socklen_t resolver_sockaddr_len;
    ev_socklen_t outgoing_sockaddr_len;
    const char *ext_address;
    const char *resolver_address;
    const char *listen_address;
    const char *outgoing_address;
    struct evconnlistener *tcp_conn_listener;
    struct event *tcp_accept_timer;
    struct event *udp_listener_event;
    struct event *udp_resolver_event;
    evutil_socket_t udp_listener_handle;
    evutil_socket_t udp_resolver_handle;
    TCPRequestQueue tcp_request_queue;
    UDPRequestQueue udp_request_queue;
    struct event_base *event_loop;
    unsigned int connections;
    size_t edns_payload_size;

    /* Domain name shared buffer. */
    char namebuff[MAXDNAME];

    /* Process stuff. */
    bool daemonize;
    bool allow_not_dnscrypted;
    char *pidfile;
    char *user;
    uid_t user_id;