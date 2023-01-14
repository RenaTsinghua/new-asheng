
#include "dnscrypt.h"
#include "block.h"

typedef struct SendtoWithRetryCtx_ {
    void (*cb) (UDPRequest *udp_request);
    const void *buffer;
    UDPRequest *udp_request;
    const struct sockaddr *dest_addr;
    evutil_socket_t handle;
    size_t length;
    ev_socklen_t dest_len;
    int flags;
} SendtoWithRetryCtx;

/* Forward declarations. */
static int sendto_with_retry(SendtoWithRetryCtx *const ctx);

#ifndef UDP_BUFFER_SIZE
# define UDP_BUFFER_SIZE 2097152
#endif
#ifndef UDP_DELAY_BETWEEN_RETRIES
# define UDP_DELAY_BETWEEN_RETRIES 1
#endif

#ifndef SO_RCVBUFFORCE
# define SO_RCVBUFFORCE SO_RCVBUF
#endif
#ifndef SO_SNDBUFFORCE
# define SO_SNDBUFFORCE SO_SNDBUF
#endif

#ifndef EVUTIL_ERR_RW_RETRIABLE
# ifndef _WIN32
#  define EVUTIL_ERR_RW_RETRIABLE(e) ((e) == EINTR || (e) == EAGAIN)
# else
#  define EVUTIL_ERR_RW_RETRIABLE(e) ((e) == WSAEWOULDBLOCK || (e) == WSAEINTR)
# endif
#endif

static int udp_request_cmp(const UDPRequest *r1, const UDPRequest *r2) {
    if (r1->hash < r2->hash) {
        return -1;
    } else if (r1->hash > r2->hash) {
        return 1;
    } else if (r1->id < r2->id) {
        return -1;
    } else if (r1->id > r2->id) {
        return 1;
    } else if (r1->gen < r2->gen) {
        return -1;
    } else if (r1->gen > r2->gen) {
        return 1;
    }
    return 0;