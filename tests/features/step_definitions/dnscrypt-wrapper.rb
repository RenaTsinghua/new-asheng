require 'net/dns'
require 'net/dns/resolver'

WRAPPER_IP = '127.0.0.1'
WRAPPER_PORT = 5443

Before do
  @resolver = Net::DNS::Resolver.new(nameserver: WRAPPER_IP, port: WRAPPER_PORT)
end

After do
  Process.kill("KILL", @pipe.pid) if @pipe
  @pipe = nil
end

Around do |scenario, block|
  Timeout.timeout(3.0) do
    block.call
  end
end

Given /^a running dnscrypt wrapper with options "([^"]*)"$/ do |options|
  str = "../dnscrypt-wrapper " +
    "--resolver-address=127.0.0.1:53 " +
    "--provider-name=2.dnscrypt-cert.example.com " +
    "--listen-address=#{WRAPPER_IP}:#{WRAPPER_PORT} #{options}"
  @pipe = IO.popen(str.split, "r")
  begin
    Timeout.timeout(0.5) do
      Process.wait @pipe.pid
      @error = @pipe.read
      @pipe = nil
    end
  rescue Timeout::Error
    # The process is still running, so it did not fail yet/
  end
end

And /^a tcp resolver$/ do
  @resolver.use_tcp = true
end

When /^a client asks dnscrypt\-wrapper for "([^"]*)" "([^"]*)" record$/ do |name, qtype|
  begin
    Timeout