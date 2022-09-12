
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