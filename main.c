#include "dnscrypt.h"
#include "argparse/argparse.h"
#include "version.h"
#include "pidfile.h"
#include "block.h"

/**
 * This is dnscrypt wrapper (server-side dnscrypt proxy), which helps to add
 * dnscrypt support to any name resolver.
 */

static const char *const config_usage[] = {
    "dnscrypt-wrapper [options]",
    NULL
};

int
show_version_cb(struct argparse *this, const struct argparse_option *option)
{
    printf("dnscrypt-wrapper %s\n", the_version);
    exit(0);
}

static int
sockaddr_from_ip_and_port(struct sockaddr_storage *const sockaddr,
                          ev_socklen_t * const sockaddr_len_p,
                          const char *const ip, const char *const port,
                          const char *const error_msg)
{
    char sockaddr_port[INET6_ADDRSTRLEN + sizeof "[]:65535"];
  