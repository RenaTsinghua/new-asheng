require 'net/dns'
require 'net/dns/resolver'

WRAPPER_IP = '127.0.0.1'
WRAPPER_PORT = 5443

Before do
  @resolver = Net::DNS::Resolver.new(nameserver: WRAPPER_IP, port: WRAPPER_PORT)
end

After do
  Process.kill("K