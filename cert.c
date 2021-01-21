
#include "dnscrypt.h"

struct SignedCert *
cert_build_cert(const uint8_t *crypt_publickey, int cert_file_expire_seconds,
                int use_xchacha20)
{
    struct SignedCert *signed_cert = malloc(sizeof(struct SignedCert));
    if (!signed_cert)
        return NULL;

    memcpy(signed_cert->magic_cert, CERT_MAGIC_CERT, 4);
    signed_cert->version_major[0] = 0;
    if (use_xchacha20) {
        signed_cert->version_major[1] = 2;
    } else {
        signed_cert->version_major[1] = 1;
    }
    signed_cert->version_minor[0] = 0;
    signed_cert->version_minor[1] = 0;

    memset(signed_cert->signature, 0, sizeof signed_cert->signature);
    memcpy(signed_cert->server_publickey, crypt_publickey,
           crypto_box_PUBLICKEYBYTES);
    memcpy(signed_cert->magic_query, crypt_publickey,
           sizeof(signed_cert->magic_query));
    if (use_xchacha20) {
        sodium_increment(signed_cert->magic_query, sizeof signed_cert->magic_query);
    }
    uint32_t ts_begin = (uint32_t)time(NULL);
    uint32_t ts_end = ts_begin + cert_file_expire_seconds;
    if (cert_file_expire_seconds <= 0) {
        ts_begin = ts_end;
    }
    ts_begin = htonl(ts_begin);
    ts_end = htonl(ts_end);
    memcpy(signed_cert->serial, &ts_begin, 4);
    memcpy(signed_cert->ts_begin, &ts_begin, 4);
    memcpy(signed_cert->ts_end, &ts_end, 4);

    return signed_cert;
}

int
cert_sign(struct SignedCert *signed_cert, const uint8_t *provider_secretkey)
{
    unsigned long long signed_data_len =
        sizeof(struct SignedCert) - offsetof(struct SignedCert,
                                             server_publickey);