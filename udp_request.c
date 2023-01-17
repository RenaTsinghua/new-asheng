
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
}

RB_GENERATE_STATIC(UDPRequestQueue_, UDPRequest_, queue, udp_request_cmp)

static void
udp_tune(evutil_socket_t const handle)
{
    if (handle == -1) {
        return;
    }
    setsockopt(handle, IPPROTO_IP, IP_TOS, (void *) (int []) {
                       0x70}, sizeof(int));
    setsockopt(handle, SOL_SOCKET, SO_RCVBUFFORCE, (void *)(int[]) {
               UDP_BUFFER_SIZE}, sizeof(int));
    setsockopt(handle, SOL_SOCKET, SO_SNDBUFFORCE, (void *)(int[]) {
               UDP_BUFFER_SIZE}, sizeof(int));
#if defined(IP_PMTUDISC_OMIT)
    setsockopt(handle, IPPROTO_IP, IP_MTU_DISCOVER,
               (void *) (int []) { IP_PMTUDISC_OMIT }, sizeof (int));
#elif defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
    setsockopt(handle, IPPROTO_IP, IP_MTU_DISCOVER, (void *)(int[]) {
               IP_PMTUDISC_DONT}, sizeof(int));
#elif defined(IP_DONTFRAG)
    setsockopt(handle, IPPROTO_IP, IP_DONTFRAG, (void *)(int[]) {
               0}, sizeof(int));
#endif
#if defined(__linux__) && defined(SO_REUSEPORT)
    setsockopt(handle, SOL_SOCKET, SO_REUSEPORT, (void *)(int[]) {
               1}, sizeof(int));
#endif
}

static void
client_to_proxy_cb_sendto_cb(UDPRequest *const udp_request)
{
    (void)udp_request;
}

static void
udp_request_kill(UDPRequest *const udp_request)
{
    if (udp_request == NULL || udp_request->status.is_dying)
        return;

    udp_request->status.is_dying = 1;

    // free
    struct context *c;
    if (udp_request->sendto_retry_timer != NULL) {
        free(event_get_callback_arg(udp_request->sendto_retry_timer));
        event_free(udp_request->sendto_retry_timer);
        udp_request->sendto_retry_timer = NULL;
    }
    if (udp_request->timeout_timer != NULL) {
        event_free(udp_request->timeout_timer);
        udp_request->timeout_timer = NULL;
    }

    c = udp_request->context;
    if (udp_request->status.is_in_queue != 0) {
        assert(!RB_EMPTY(&c->udp_request_queue));
        RB_REMOVE(UDPRequestQueue_, &c->udp_request_queue, udp_request);
        assert(c->connections > 0);
        c->connections--;
    }

    udp_request->context = NULL;
    free(udp_request);
}

int
udp_listener_kill_oldest_request(struct context *c)
{
    if (RB_EMPTY(&c->udp_request_queue))
        return -1;

    udp_request_kill(RB_MIN(UDPRequestQueue_, &c->udp_request_queue));

    return 0;
}

static void
sendto_with_retry_timer_cb(evutil_socket_t retry_timer_handle, short ev_flags,
                           void *const ctx_)
{
    SendtoWithRetryCtx *const ctx = ctx_;

    (void)ev_flags;
    assert(retry_timer_handle ==
           event_get_fd(ctx->udp_request->sendto_retry_timer));

    sendto_with_retry(ctx);
}

static int
sendto_with_retry(SendtoWithRetryCtx *const ctx)
{
    void (*cb) (UDPRequest *udp_request);
    SendtoWithRetryCtx *ctx_cb;
    UDPRequest *udp_request = ctx->udp_request;
    int err;
    bool retriable;

    if (sendto(ctx->handle, ctx->buffer, ctx->length, ctx->flags,
               ctx->dest_addr, ctx->dest_len) == (ssize_t) ctx->length) {
        cb = ctx->cb;
        if (udp_request->sendto_retry_timer != NULL) {
            ctx_cb = event_get_callback_arg(udp_request->sendto_retry_timer);
            assert(ctx_cb != NULL);
            assert(ctx_cb->udp_request == ctx->udp_request);
            assert(ctx_cb->buffer == ctx->buffer);
            free(ctx_cb);
            event_free(udp_request->sendto_retry_timer);
            udp_request->sendto_retry_timer = NULL;
        }
        if (cb) {
            cb(udp_request);
        }
        return 0;
    }

    err = evutil_socket_geterror(udp_request->client_proxy_handle);
    logger(LOG_WARNING, "sendto: [%s]", evutil_socket_error_to_string(err));

    retriable = (err == ENOBUFS || err == ENOMEM ||
                 err == EAGAIN || err == EINTR);

    if (retriable == 0) {
        udp_request_kill(udp_request);
        return -1;
    }
    assert(DNS_QUERY_TIMEOUT < UCHAR_MAX);
    if (++(udp_request->retries) > DNS_QUERY_TIMEOUT) {
        udp_request_kill(udp_request);
        return -1;
    }
    if (udp_request->sendto_retry_timer != NULL) {
        ctx_cb = event_get_callback_arg(udp_request->sendto_retry_timer);
        assert(ctx_cb != NULL);
        assert(ctx_cb->udp_request == ctx->udp_request);
        assert(ctx_cb->buffer == ctx->buffer);
    } else {
        if ((ctx_cb = malloc(sizeof *ctx_cb)) == NULL) {
            udp_request_kill(udp_request);
            return -1;
        }
        assert(ctx_cb ==
               event_get_callback_arg(udp_request->sendto_retry_timer));
        *ctx_cb = *ctx;
        if ((udp_request->sendto_retry_timer =
             evtimer_new(udp_request->context->event_loop,
                         sendto_with_retry_timer_cb, ctx_cb)) == NULL) {
            free(ctx_cb);
            udp_request_kill(udp_request);
            return -1;
        }
    }
    const struct timeval tv = {
        .tv_sec = (time_t) UDP_DELAY_BETWEEN_RETRIES,.tv_usec = 0
    };
    evtimer_add(udp_request->sendto_retry_timer, &tv);
    return -1;

}

static void
timeout_timer_cb(evutil_socket_t timeout_timer_handle, short ev_flags,
                 void *const udp_request_)
{
    UDPRequest *const udp_request = udp_request_;

    (void)ev_flags;
    (void)timeout_timer_handle;
    logger(LOG_DEBUG, "resolver timeout (UDP)");
    udp_request_kill(udp_request);
}

/**
 * Return 0 if served.
 */
static int
self_serve_cert_file(struct context *c, struct dns_header *header,
                     size_t dns_query_len, size_t max_len, UDPRequest *udp_request)
{
    int ret = dnscrypt_self_serve_cert_file(c, header, &dns_query_len, max_len);
    if (ret == 0) {
        SendtoWithRetryCtx retry_ctx = {
            .udp_request = udp_request,
            .handle = udp_request->client_proxy_handle,
            .buffer = header,
            .length = dns_query_len,
            .flags = 0,
            .dest_addr = (struct sockaddr *)&udp_request->client_sockaddr,
            .dest_len = udp_request->client_sockaddr_len,
            .cb = udp_request_kill