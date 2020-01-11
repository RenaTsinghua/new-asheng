# CHANGELOG

## Table of Contents

* [v0.4.2](#v042)
* [v0.4.1](#v041)
* [v0.4.0](#v040)
* [v0.3.0](#v030)
* [v0.2.2](#v022)
* [v0.2.1](#v021)
* [v0.2.0](#v020)

## v0.4.2

- Log level of "suspicious query" changed to debug

## v0.4.1

- find_cert() should search in all certs, fixes #139.
- filter_signed_certs() should converts serial to uint32_t before comparison.
- --cert-file-expire-days supports 'd', 'h', 'm', 's' suffixes

## v0.4.0

- Use sodium_malloc() for the DNS query/response buffers
- Fix stamp properties; add --nofilter
- Only publish the most recent certificates
- Include the signature in SignedCert
- cache: do not forget to include the server PK in the hash computation
- Implement a simple cache for shared keys
- Add support for stamps (dnscrypt-proxy 2.x), and update the documentation
- In key rotation, old certs should be provided too, see #109.
- fixes #111, cert/key e