
#include "dnscrypt.h"

typedef struct Cached_ {
    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t server_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t shared[crypto_box_BEFORENMBYTES];
} Cached;

static Cached cache[4096];

static inline size_t
h12(const uint8_t pk[crypto_box_PUBLICKEYBYTES],
    const uint8_t server_pk[crypto_box_PUBLICKEYBYTES], bool use_xchacha20)
{
    uint64_t a, b, c, d, e;
    uint32_t h;

    memcpy(&a, &pk[0], 8);  memcpy(&b, &pk[8], 8);
    memcpy(&c, &pk[16], 8); memcpy(&d, &pk[24], 8);
    e = a ^ b ^ c ^ d;
    memcpy(&a, &server_pk[0], 8);  memcpy(&b, &server_pk[8], 8);
    memcpy(&c, &server_pk[16], 8); memcpy(&d, &server_pk[24], 8);
    e ^= a ^ b ^ c ^ d;
    h = ((uint32_t) e) ^ ((uint32_t) (e >> 32));
    return (size_t) (((h >> 20) ^ (h >> 8) ^ (h << 4) ^ use_xchacha20) & 0xfff);
}

static int
cache_get(Cached ** const cached_p,
          const uint8_t pk[crypto_box_PUBLICKEYBYTES],
          const uint8_t server_pk[crypto_box_PUBLICKEYBYTES], const bool use_xchacha20)
{
    Cached *cached = &cache[h12(pk, server_pk, use_xchacha20)];

    *cached_p = cached;
    if (memcmp(cached->pk, pk, crypto_box_PUBLICKEYBYTES - 1) == 0 &&
        (cached->pk[crypto_box_PUBLICKEYBYTES - 1] ^ use_xchacha20) == pk[crypto_box_PUBLICKEYBYTES - 1] &&
        memcmp(cached->server_pk, server_pk, crypto_box_PUBLICKEYBYTES - 1) == 0) {
        return 1;
    }
    return 0;
}

static void
cache_set(const uint8_t shared[crypto_box_BEFORENMBYTES],
          const uint8_t pk[crypto_box_PUBLICKEYBYTES],
          const uint8_t server_pk[crypto_box_PUBLICKEYBYTES], const bool use_xchacha20)
{
    Cached *cached;

    cache_get(&cached, pk, server_pk, use_xchacha20);
    memcpy(cached->pk, pk, crypto_box_PUBLICKEYBYTES);
    cached->pk[crypto_box_PUBLICKEYBYTES - 1] ^= use_xchacha20;
    memcpy(cached->server_pk, server_pk, crypto_box_PUBLICKEYBYTES);
    memcpy(cached->shared, shared, crypto_box_BEFORENMBYTES);
}

const dnsccert *
find_cert(const struct context *c,
          const unsigned char magic_query[DNSCRYPT_MAGIC_HEADER_LEN],
          const size_t dns_query_len)
{
    const dnsccert *certs = c->certs;
    size_t i;

    if (dns_query_len <= DNSCRYPT_QUERY_HEADER_SIZE) {
        return NULL;
    }
    for (i = 0U; i < c->certs_count; i++) {
        if (memcmp(certs[i].magic_query, magic_query, DNSCRYPT_MAGIC_HEADER_LEN) == 0) {
            return &certs[i];
        }
    }
    if (memcmp(magic_query, CERT_OLD_MAGIC_HEADER, DNSCRYPT_MAGIC_HEADER_LEN) == 0) {
        return &certs[0];
    }
    return NULL;
}

int
dnscrypt_cmp_client_nonce(const uint8_t
                          client_nonce[crypto_box_HALF_NONCEBYTES],
                          const uint8_t *const buf, const size_t len)
{
    const size_t client_nonce_offset = sizeof(DNSCRYPT_MAGIC_RESPONSE) - 1;

    if (len < client_nonce_offset + crypto_box_HALF_NONCEBYTES
        || memcmp(client_nonce, buf + client_nonce_offset,
                  crypto_box_HALF_NONCEBYTES) != 0) {
        return -1;
    }

    return 0;
}

uint64_t
dnscrypt_hrtime(void)
{
    struct timeval tv;
    uint64_t ts = (uint64_t)0U;
    int ret;

    ret = evutil_gettimeofday(&tv, NULL);
    assert(ret == 0);
    if (ret == 0) {
        ts = (uint64_t)tv.tv_sec * 1000000U + (uint64_t)tv.tv_usec;
    }
    return ts;
}

void
dnscrypt_key_to_fingerprint(char fingerprint[80U], const uint8_t *const key)
{
    const size_t fingerprint_size = 80U;
    size_t fingerprint_pos = (size_t) 0U;
    size_t key_pos = (size_t) 0U;

    COMPILER_ASSERT(crypto_box_PUBLICKEYBYTES == 32U);
    COMPILER_ASSERT(crypto_box_SECRETKEYBYTES == 32U);
    for (;;) {
        assert(fingerprint_size > fingerprint_pos);
        evutil_snprintf(&fingerprint[fingerprint_pos],
                        fingerprint_size - fingerprint_pos, "%02X%02X",
                        key[key_pos], key[key_pos + 1U]);
        key_pos += 2U;
        if (key_pos >= crypto_box_PUBLICKEYBYTES) {
            break;
        }
        fingerprint[fingerprint_pos + 4U] = ':';
        fingerprint_pos += 5U;
    }
}

static int
_dnscrypt_parse_char(uint8_t key[crypto_box_PUBLICKEYBYTES],
                     size_t * const key_pos_p, int *const state_p,
                     const int c, uint8_t *const val_p)
{
    uint8_t c_val;

    switch (*state_p) {
    case 0:
    case 1:
        if (isspace(c) || (c == ':' && *state_p == 0)) {
            break;
        }
        if (c == '#') {
            *state_p = 2;
            break;
        }
        if (!isxdigit(c)) {
            return -1;
        }
        c_val = (uint8_t)((c >= '0' && c <= '9') ? c - '0' : c - 'a' + 10);
        assert(c_val < 16U);
        if (*state_p == 0) {
            *val_p = c_val * 16U;
            *state_p = 1;
        } else {
            *val_p |= c_val;
            key[(*key_pos_p)++] = *val_p;
            if (*key_pos_p >= crypto_box_PUBLICKEYBYTES) {
                return 0;
            }
            *state_p = 0;
        }
        break;
    case 2:
        if (c == '\n') {
            *state_p = 0;
        }
    }
    return 1;
}

int
dnscrypt_fingerprint_to_key(const char *const fingerprint,
                            uint8_t key[crypto_box_PUBLICKEYBYTES])
{
    const char *p = fingerprint;
    size_t key_pos = (size_t) 0U;
    int c;
    int ret;
    int state = 0;
    uint8_t val = 0U;

    if (fingerprint == NULL) {
        return -1;
    }
    while ((c = tolower((int)(unsigned char)*p)) != 0) {
        ret = _dnscrypt_parse_char(key, &key_pos, &state, c, &val);
        if (ret <= 0) {
            return ret;
        }
        p++;
    }
    return -1;