Feature: Test certs in TXT records

  Test if dnscrypt-wrapper returns the certificate in TXT records

  Scenario: query provider-name, TXT record, multiple certificates
    """
    Check that we can serve re