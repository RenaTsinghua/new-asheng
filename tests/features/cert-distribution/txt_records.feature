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
    Given a running dnscrypt wrapper with options "--crypt-secretkey-file=1.key,keys1/1.key,keys2/1.key --provider-cert-file=1.cert,keys1/1.