# Certman - Certificate Manager
A script that automates OpenSSL certificate management; it can handle certificate issuance, revocation, and validation, as it provides both OCSP responder and CRL.

## Requierments:
    - OpenSSL 1.1.1k
    - Nginx
    - Redhat 7/8 based distribution


## Overview
The way this script works is that it initiates a Root certificate and then an intermediate certificate which then gets used for signing certificates, signing OCSP responses, and generating the CRL.
The Root certificate can be either generated or imported as an existing certificate; however, the intermediate certificate is always generated and it doesn't use a passphrase, the reason being both OCSP and CRL scripts will require the passphrase to be automatically started by systemd, providing the passphrase to these scripts doesn't provide extra security as any root user will be able to modify the scripts and extract the passwords, therefore, it's much easier to just use an intermediate certificate and revoke that certificate if the private key is compromised.

For lab environments, this isn't a big deal, but if you want to be extra secure, you can use your existing Certificate Authority to generate a new certificate with an OCSP responder, then import the generated certificate to Certman this way, you can remotely revoke the entire chain if needed, but you need to keep in mind that your client needs to trust the entire chain.

## Usage:

    -in | --Install     Requires one of the following options 'clean, crl, ocsp'.
    -in clean           Remove the previous installation and prompt for a fresh install.
    -in crl             Install and configure CRL server.
    -in ocsp            Install and configure OCSP responder.

    -un | --uninstall   Uninstall and clean up all the changes made by installing Certman.

    -im | --import      Import an existing Certificate as ROOT CA instead of generating a new one.
                        Requires A certificate file and A certificate key file.
                        Example: --import myca.pem myca.key

    -st | --state       Check the status of OCSP and CRL services.

    -g  | --generate    Generate a key and a signed Certificate.
    -g test.domain      Use the FQDN 'test.domain' instead of prompting for FQDN.
    -g -f file          Output the Key and Certificate to 'file.key' and 'file.pem'.

    -s  | --sign        Sign an existing csr.

    -r  | --revoke      Revoke a certificate.

    -l  | --list        List valid certificates.

    -l -a               List all certificates.
