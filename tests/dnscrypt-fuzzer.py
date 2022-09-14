
#!/usr/bin/env python
"""

Requirements:
* https://github.com/openalias/dnscrypt-python
* https://github.com/warner/python-pure25519/blob/master/misc/djbec.py
* a query file of the form `qname\tqtype`. Example query file https://nominum.com/measurement-tools/


Example usage:
python dnscrypt-fuzzer.py \
    --provider-key XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX \
    --port 8443 \
    -q queryfile-example-current
"""
import argparse
import codecs
import os
import pdb
import random
import socket
import time

import dnscrypt

qtypemap = {
    'A': 1,
    'NS': 2,
    'MD': 3,
    'MF': 4,
    'CNAME': 5,
    'SOA': 6,
    'MB': 7,
    'MG': 8,
    'MR': 9,
    'NULL': 10,
    'WKS': 11,
    'PTR': 12,
    'HINFO': 13,
    'MINFO': 14,
    'MX': 15,
    'TXT': 16,
    'RP': 17,
    'AFSDB': 18,
    'X25': 19,
    'ISDN': 20,
    'RT': 21,
    'NSAP': 22,
    'NSAP-PTR': 23,
    'SIG': 24,
    'KEY': 25,
    'PX': 26,
    'GPOS': 27,
    'AAAA': 28,
    'LOC': 29,
    'NXT': 30,
    'EID': 31,
    'NIMLOC': 32,
    'SRV': 33,
    'ATMA': 34,
    'NAPTR': 35,
    'KX': 36,
    'CERT': 37,
    'A6': 38,
    'DNAME': 39,
    'SINK': 40,
    'OPT': 41,
    'APL': 42,
    'DS': 43,
    'SSHFP': 44,
    'IPSECKEY': 45,
    'RRSIG': 46,
    'NSEC': 47,
    'DNSKEY': 48,
    'DHCID': 49,
    'NSEC3': 50,
    'NSEC3PARAM': 51,
    'TLSA': 52,
    'SMIMEA': 53,
    'Unassigned': 54,
    'HIP': 55,
    'NINFO': 56,
    'RKEY': 57,
    'TALINK': 58,
    'CDS': 59,
    'CDNSKEY': 60,
    'OPENPGPKEY': 61,
    'CSYNC': 62,
    'SPF': 99,
    'UINFO': 100,
    'UID': 101,
    'GID': 102,
    'UNSPEC': 103,
    'NID': 104,
    'L32': 105,
    'L64': 106,
    'LP': 107,
    'EUI48': 108,
    'EUI64': 109,
    'TKEY': 249,
    'TSIG': 250,
    'IXFR': 251,
    'AXFR': 252,
    'MAILB': 253,
    'MAILA': 254,
    '*': 255,
    'URI': 256,
    'CAA': 257,
    'AVC': 258,
    'TA': 32768,
    'DLV': 32769,
}

def flipbit(msg, **kwargs):
    idx = random.randint(0, len(msg)-1)
    bit_idx = random.randint(0,7)
    x = msg[:idx]
    x += chr(ord(msg[idx]) ^ 1<<bit_idx)
    x += msg[idx+1:]
    return x

def flipmanybits(msg, **kwargs):

    x = ''
    for c in msg:
        if random.randint(0, 50) == 25:
            bit_idx = random.randint(0,7)
            x += chr(ord(c) ^ 1<<bit_idx)
        else:
            x += c
    return x

def dropbyte(msg, **kwargs):
    idx = random.randint(0, len(msg)-1)
    return msg[:idx] + msg[idx+1:]

def injectbyte(msg, **kwargs):
    idx = random.randint(0, len(msg)-1)
    x = msg[:idx]
    x += chr(random.randint(0, 255))
    x += msg[idx:]
    return x

def truncatepacket(msg, **kwargs):
    idx = random.randint(kwargs['minint'], len(msg)-1)
    return msg[idx:]

def noop(msg, **kwargs):
    return msg

def mkmsg(magic_query, pk, nonce, encoded_message):
    return magic_query + pk + nonce + encoded_message

def corrupt(magic_query, pk, nonce, nmkey, message):
    c = random.randint(0, 100) % 7
    args = {}
    if c <= 1:
        f = flipmanybits
    elif c == 2:
        f = flipbit
    elif c == 3:
        f = dropbyte
    elif c == 4:
        f = injectbyte
    elif c == 5:
        # 68 is min dnscrypt header size
        args = {'minint': 68}
        f = truncatepacket
    elif c == 6:
        c2 = random.randint(0, 100) % 4
        f = flipmanybits
        if c2 == 0:
            f = flipbit
        elif c2 == 1:
            f = dropbyte
        elif c2 == 2:
            f = injectbyte
        elif c2 == 3:
            # 12 is min dns header size