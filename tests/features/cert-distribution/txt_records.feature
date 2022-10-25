Feature: Test certs in TXT records

  Test if dnscrypt-wrapper returns the certificate in TXT records

  Scenario: query provider-name, TXT record, multiple certificates
    """
    Check that we can serve recent certificate.
    """
    # Generate a fresh cert.
    Given a provider keypair
    And a time limited secret key
    When a xsalsa20 cert is generated
    Then it is a xsalsa20 cert
    Given a running dnscrypt wrapper with options "--crypt-secretkey-file=1.key,keys1/1.key,keys2/1.key --provider-cert-file=1.cert,keys1/1.cert,keys2/1.cert"
    When a client asks dnscrypt-wrapper for "2.dnscrypt-cert.example.com" "TXT" record
    Then dnscrypt-wrapper returns "1.cert"
    Then dnscrypt-wrapper does not return "keys1/1.cert"
    Then dnscrypt-wrapper does not return "keys2/1.cert"

  Scenario: query provider-name, TXT record, multiple certificates and TCP resolver
    """
    Check that we can serve recent certificate over TCP.
    """
    # Generate a fresh cert.
    Given a provider keypair
    And a time limited secret key
    When a xsalsa20 cert is generated
    Then it is a xsalsa20 cert
    Given a running dnscrypt wrapper with options "--crypt-secretkey-file=1.key,keys1/1.key,keys2/1.key --provider-cert-file=1.cert,keys1/1.cert,keys2/1.cert"
    And a tcp resolver
    When a client asks dnscrypt-wrapper for "2.dnscrypt-cert.example.com" "TXT" record
    Then dnscrypt-wrapper returns "1.cert"
    Then dnscrypt-wrapper does not return "keys1/1.cert"
    Then dnscrypt-wrapper does not return "keys2/1.cert"

  Scenario: query provider-name, TXT record, multiple esversion same key
    """
    Check that we can serve recent certs with different ES versions
    for the same key.
    """
    # Generate a fresh cert.
    Given a provider keypair
    And a time limited secret key
    When a xsalsa20 cert is generated
    Then it is a xsalsa20 cert
    Given a running dnscrypt wrapper with options "--crypt-secretkey-file=1.key  --provider-cert-file=1.cert,keys1/1.cert,keys2/1.cert,keys2/1.xchacha20.cert"
    When a client asks dnscrypt-wrapper for "2.dnscrypt-cert.example.com" "TXT" record
    Then dnscrypt-wrapper returns "1.cert"
    Then dnscryp