# Cryptos
This library implements exactly one "good" industry best practices method for symmetric and asymmetric encryption.
For symmetric encryption, AES-256 is used to encrypt and decrypt.
For asymmetric encryption, RSA is used to sign and verify signatures; and encrypt and decrypt using RSA/AES-256.

# Unit Tests
The CryptosTest\Data folder requires the following files:
* **private.pem** that contains the private key.
* **certificate.pem** that contains the public key.
* **certificate.pfx** that contains the public and the private key.

These two pem files (the key pair) can be generated on the git bash shell with the following command:
```
openssl req -newkey rsa:2048 -nodes -keyout private.pem -x509 -days 9999999 -out certificate.pem
```

You can optionally verify the certificate with:
```
openssl x509 -text -noout -in certificate.pem
openssl pkey -text -noout -in private.pem
```

You can also export the key pair as PKCS#12 format (e.g *.pfx i.e. *.p12). We'll use "hello" as the password, which these files demand:
```
openssl pkcs12 -inkey private.pem -in certificate.pem -export -out certificate.pfx -passout pass:hello
openssl pkcs12 -in certificate.pfx -noout -info -passout pass:hello

openssl asn1parse -in private.pem
openssl asn1parse -in private.pem -strparse 22

```
