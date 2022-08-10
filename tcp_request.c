
#include "dnscrypt.h"
#include "block.h"

static void
tcp_request_kill(TCPRequest *const tcp_request)
{
    if (tcp_request == NULL || tcp_request->status.is_dying) {
        return;
    }
    tcp_request->status.is_dying = 1;
    struct context *c;

    if (tcp_request->timeout_timer != NULL) {
        event_free(tcp_request->timeout_timer);
        tcp_request->timeout_timer = NULL;
    }
    if (tcp_request->client_proxy_bev != NULL) {
        bufferevent_free(tcp_request->client_proxy_bev);
        tcp_request->client_proxy_bev = NULL;
    }
    if (tcp_request->proxy_resolver_bev != NULL) {
        bufferevent_free(tcp_request->proxy_resolver_bev);
        tcp_request->proxy_resolver_bev = NULL;
    }
    if (tcp_request->proxy_resolver_query_evbuf != NULL) {
        evbuffer_free(tcp_request->proxy_resolver_query_evbuf);
        tcp_request->proxy_resolver_query_evbuf = NULL;
    }
    c = tcp_request->context;
    if (tcp_request->status.is_in_queue != 0) {
        debug_assert(!TAILQ_EMPTY(&c->tcp_request_queue));
        TAILQ_REMOVE(&c->tcp_request_queue, tcp_request, queue);
        debug_assert(c->connections > 0U);
        c->connections--;
    }
    tcp_request->context = NULL;
    free(tcp_request);