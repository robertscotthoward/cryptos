# Cryptos - Simple RSA/AES Cryptography in C#
This managed C# .NET Standard 2.0 library implements exactly one "good" industry best practices method for symmetric and asymmetric cryptography.
For symmetric encryption, AES-256 (with a random salt) is used to encrypt and decrypt.
For asymmetric encryption, RSA (1024, 2048, 4096) is used to sign and verify signatures; 
and encrypt and decrypt using RSA/AES-256.
This library only implements the minimum, most convenient methods
needed to perform the most popular cryptographic operations. It has no dependencies on other libraries.

# Architectural Constraints
The design considerations that drive this library are:
* No configuration or choices - one good method; not twenty. Convention over configuration.
* Easy, intuitive, convenient interface.
* No dependencies on other libraries
* Minimal code files.
* Use openssl on the git bash shell to generate asymmetric key pair files.
* Use password-protected PFX files as well as base-64-encoded PEM files.

# Use Cases
This section shows how to encrypt, decrypt, sign, and verify 
using RSA-2048, and encrypt and decrypt using AES-256. 
Asymmetric Encryption and signature verification only requires 
the public key; i.e. the certificate. To decrypt and sign requires
the private key as well. Depending on what you have determines what 
you can do.

## Symmetric
Let's encrypt a string message using AES-256 and a password to get an encrypted
base-64 string. Then decrypt it using the same password to recover 
the message.
```
var message = "Attack at dawn!";
var password = "Shhhhh!";
var cipher = Symmetric.Encrypt(message);
Assert.AreEqual(message, Symmetric.Decrypt(cipher, password));
```

The bytes example is:
```
byte[] messageBytes = { 0x25, 0x9F, 0xB3 };
byte[] passwordBytes = { 0x12, 0x34, 0x56, 0x78 };
Assert.AreEqual(messageBytes.ToBase64(), Symmetric.Decrypt(Symmetric.Encrypt(messageBytes, passwordBytes), passwordBytes).ToBase64());
```

## Asymmetric using pfx file
A PFX (Personal Information Exchange Format) file is a file that contains a key pair but is protected
by a password.

```
var message = "Attack at dawn!";
var password = "hello"; // The password to the pfx file.
var path = @"C:\temp\mykeypair.pfx";
var rsa = new Asymmetric(path, password);

var rsa = new Asymmetric(Path.Join(path, @"Data\certificate.pfx"), password);

var signature = rsa.Sign(message);
Assert.IsTrue(rsa.Verify(message, signature));

var cipher = rsa.Encrypt(message);
Assert.AreEqual(message, rsa.Decrypt(cipher));
```

## Asymmetric using pem files
See Unit Tests below for instructions on how to create key pairs in
pem files and also in a pfx file for importing into Windows. 
```
var pem = File.ReadAllText("certificate.pem");
var rsa = Asymmetric.FromPem(pem);
var cipher = rsa.Encrypt(message);
rsa.Verify(message, signature);
```

By concatenating the public PEM to private PEM, we can decrypt and verify too.
```
var pem = File.ReadAllText("certificate.pem") + File.ReadAllText("private.pem");
var rsa = Asymmetric.FromPem(pem);
var cipher = rsa.Encrypt(message);
message = rsa.Decrypt(cipher);
rsa.Verify(message, signature);

```

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
```
And if you are curious about ASN.1, you can dump it this way:
```
openssl asn1parse -in private.pem
openssl asn1parse -in private.pem -strparse 22
```

This nice tool exists to look into these files: https://www.sysadmins.lv/projects/asn1editor/default.aspx

# Notes
* AES is the standard. Rijndael is the implementation. 
* 256-bit symmetric AES encryption is quantum safe. They won't crack it.
* RSA can only encrypt messages of perhaps 240 bytes or less. So this implementation asymmetrically encryptes a
one-time pad (random 32-byte symmetric key) and uses AES-256 to encrypt longer messages.
* All methods (Encrypt, Decrypt, Sign, and Verify) take a byte array in and return a byte array out. 
But these methods each have a convenient sibling that takes a string in and returns a string out to make 
it easy to work with most web applications and cloud solutions. 
Cipher text and signatures in these cases are base-64 encoded.
