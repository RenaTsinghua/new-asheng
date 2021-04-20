
#include "dnscrypt.h"

typedef struct Cached_ {
    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t server_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t shared[crypto_box_BEFORENMBYTES];