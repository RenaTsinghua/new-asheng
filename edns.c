
#include "dnscrypt.h"

static int
_skip_name(const uint8_t *const dns_packet, const size_t dns_packet_len,
           size_t * const offset_p)
{
    size_t offset = *offset_p;
    uint8_t name_component_len;

    if (dns_packet_len < (size_t) 1U || offset >= dns_packet_len - (size_t) 1U) {
        return -1;
    }
    do {
        name_component_len = dns_packet[offset];
        if ((name_component_len & 0xC0) == 0xC0) {
            name_component_len = 1U;
        }
        if (name_component_len >= dns_packet_len - offset - 1U) {
            return -1;
        }
        offset += name_component_len + 1U;
    } while (name_component_len != 0U);
    if (offset >= dns_packet_len) {
        return -1;
    }
    *offset_p = offset;

    return 0;
}

#define DNS_QTYPE_PLUS_QCLASS_LEN 4U

static ssize_t
edns_get_payload_size(const uint8_t *const dns_packet,
                      const size_t dns_packet_len)
{
    size_t offset;
    size_t payload_size;
    unsigned int arcount;

    assert(dns_packet_len >= DNS_HEADER_SIZE);
    arcount = (dns_packet[DNS_OFFSET_ARCOUNT] << 8) |
        dns_packet[DNS_OFFSET_ARCOUNT + 1U];
    assert(arcount > 0U);
    assert(DNS_OFFSET_QUESTION <= DNS_HEADER_SIZE);
    if (dns_packet[DNS_OFFSET_QDCOUNT] != 0U ||
        dns_packet[DNS_OFFSET_QDCOUNT + 1U] != 1U ||
        (dns_packet[DNS_OFFSET_ANCOUNT] |
         dns_packet[DNS_OFFSET_ANCOUNT + 1U]) != 0U ||
        (dns_packet[DNS_OFFSET_NSCOUNT] |
         dns_packet[DNS_OFFSET_NSCOUNT + 1U]) != 0U) {
        return (ssize_t) - 1;
    }
    offset = DNS_OFFSET_QUESTION;
    if (_skip_name(dns_packet, dns_packet_len, &offset) != 0) {
        return (ssize_t) - 1;
    }
    assert(dns_packet_len > (size_t) DNS_QTYPE_PLUS_QCLASS_LEN);
    if (offset >= dns_packet_len - (size_t) DNS_QTYPE_PLUS_QCLASS_LEN) {
        return (ssize_t) - 1;
    }
    offset += DNS_QTYPE_PLUS_QCLASS_LEN;
    assert(dns_packet_len >= DNS_OFFSET_EDNS_PAYLOAD_SIZE + 2U);