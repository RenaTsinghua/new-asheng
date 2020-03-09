
# Name

dnscrypt-wrapper - A server-side dnscrypt proxy.

[![Build Status](https://travis-ci.org/cofyc/dnscrypt-wrapper.png?branch=master)](https://travis-ci.org/cofyc/dnscrypt-wrapper)

## Table of Contents

* [Description](#description)
* [Installation](#installation)
* [Usage](#usage)
  * [Quick start](#quick-start)
  * [Running unauthenticated DNS and the dnscrypt service on the same port](#running-unauthenticated-dns-and-the-dnscrypt-service-on-the-same-port)
  * [Key rotation](#key-rotation)
* [Chinese](#chinese)
* [See also](#see-also)

## Description

This is dnscrypt wrapper (server-side dnscrypt proxy), which helps to
add dnscrypt support to any name resolver.

This software is modified from
[dnscrypt-proxy](https://github.com/jedisct1/dnscrypt-proxy).

## Installation

Install [libsodium](https://github.com/jedisct1/libsodium) and [libevent](http://libevent.org/) 2.1.1+ first.

On Linux:

    $ ldconfig # if you install libsodium from source
    $ git clone git://github.com/cofyc/dnscrypt-wrapper.git
    $ cd dnscrypt-wrapper
    $ make configure
    $ ./configure
    $ make install

On FreeBSD:

    $ pkg install dnscrypt-wrapper

On OpenBSD:

    $ pkg_add -r gmake autoconf
    $ pkg_add -r libevent
    $ git clone git://github.com/cofyc/dnscrypt-wrapper.git
    $ cd dnscrypt-wrapper
    $ gmake LDFLAGS='-L/usr/local/lib/' CFLAGS=-I/usr/local/include/

On MacOS:

    $ brew install dnscrypt-wrapper

In Docker:

    See https://github.com/jedisct1/dnscrypt-server-docker.

## Usage

### Quick Start

1) Generate the provider key pair:

```sh
$ dnscrypt-wrapper --gen-provider-keypair \
  --provider-name=2.dnscrypt-cert.<yourdomain> --ext-address=<external server ip>
```

If your server doesn't store logs, add `--nolog` and if it supports DNSSEC,
add `--dnssec`.

This will create two files in the current directory: `public.key` and
`secret.key`.

This is a long-term key pair that is never supposed to change unless the
secret key is compromised. Make sure that `secret.key` is securely
stored and backuped.

It will also print the stamp for dnscrypt-proxy version 2.x.

If you forgot to save your provider public key:

```sh
$ dnscrypt-wrapper --show-provider-publickey --provider-publickey-file <your-publickey-file>
```

This will print it out.

2) Generate a time-limited secret key, which will be used to encrypt
and authenticate DNS queries. Also generate a certificate for it:

```sh
$ dnscrypt-wrapper --gen-crypt-keypair --crypt-secretkey-file=1.key
$ dnscrypt-wrapper --gen-cert-file --crypt-secretkey-file=1.key --provider-cert-file=1.cert \