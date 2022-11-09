require 'net/dns'
require 'net/dns/resolver'

WRAPPER_IP = '127.0.0.1'
WRAPPER_PORT = 5443

Before do
  @resolver = Net::DNS: