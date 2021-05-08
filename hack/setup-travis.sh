#!/bin/bash

set -x

# Install unbound so we can test dnscrypt-wrapper.
apt-get install -y unbound

# Workaround where t