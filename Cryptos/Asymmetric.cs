/********************************************************************************
WRITTEN:
  2011-05-18
AUTHOR:
  Robert Howard
DESCRIPTION:
  Wrap up the complexity of signing and decrypting a message using a PFX file
  and verifying digital signatures and encrypting a message using a CER file.
NOTES:
  A CER file contains a signed public key.
  A PFX file contains a public key and a password-protected private key.
  The CER can be used by anyone to verify signatures and encrypt messages.
  The PFX can be used only by the original author to create signatures and decrypt messages.
REFERENCES:
  To create CER and PFX files, see the README.md file.
 ********************************************************************************/

using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Cryptos
{
    public class Asymmetric
    {
        X509Certificate2 cert;
        RSA _pri;
        RSA _pub;
        readonly string _hash;

        public Asymmetric(string pathToPfx, string password, string hash = "SHA256")
        {
            _hash = hash;
            cert = new X509Certificate2(pathToPfx, password, X509KeyStorageFlags.DefaultKeySet);
            Init();
        }

        /// <summary>
        /// Create a cryptographic object from the path to a PFX file.
        /// </summary>
        /// <param name="bytes">The bytes of a CER or PFX file.</param>
        /// <param name="hash"></param>
        public Asymmetric(byte[] bytes, string hash = "SHA256")
        {
            _hash = hash;
            cert = new X509Certificate2(new X509Certificate(bytes));
            Init();
        }

        /// <summary>
        /// Convert a pem file into an object. It must contain the certificate, but it can optionally contain the private key.
        /// </summary>
        /// <param name="pem"></param>
        /// <param name="hashAlgorithm"></param>
        /// <returns></returns>
        public static Asymmetric FromPem(string pem, string hashAlgorithm = "SHA256")
        {
            var s = pem.Between("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----").RemoveWhiteSpace();
            var certBytes = s.FromBase64();

            s = pem.Between("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----").RemoveWhiteSpace();
            var priBytes = s.FromBase64();

            var cert = new Asymmetric(certBytes, hashAlgorithm);

            Debug.Print(priBytes.ToHex());

            if (priBytes.Length > 0)
            {
                var rsaParameters = PemToParameters(priBytes);
                var rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(rsaParameters);
                cert._pri = rsa;
            }

            return cert;
        }

        void Init()
        {
            cert.Verify();
            _pri = (RSA)cert.PrivateKey;
            _pub = (RSA)cert.PublicKey.Key;
        }

        /// <summary>
        /// The Decrypt and Sign require the private key. Assert that this object has been constructed with the PFX
        /// file, which contains the public and the private key.
        /// </summary>
        private void AssertPrivate()
        {
            if (_pri == null)
                throw new Exception("This method requires the private key. You probably used the CER file to construct this Cryptos object. Use the PFX file instead. The CER file only contains the public key. The PFX file contains both the public and the private key.");
        }

        /// <summary>
        /// Create a digital signature for a plaintext message using the private key.
        /// </summary>
        /// <param name="message">Any message to sign.</param>
        /// <returns>A digital signature.</returns>
        public byte[] Sign(byte[] message) { AssertPrivate(); return _pri.SignData(message, new HashAlgorithmName(_hash), RSASignaturePadding.Pkcs1); }

        /// <summary>
        /// By using only the public key, verify that a signature was indeed created for a given message with the private key.
        /// </summary>
        /// <param name="message">Any message to verify. This is the same message that was passed into the Sign() method 
        /// to create the digital signature.</param>
        /// <param name="signature">The signature returned from calling the Sign() method.</param>
        /// <returns></returns>
        public bool Verify(byte[] message, byte[] signature) { return _pub.VerifyData(message, signature, new HashAlgorithmName(_hash), RSASignaturePadding.Pkcs1); }

        /// <summary>
        /// This method will likely throw an exception if the message is longer than 200-ish bytes.
        /// It is only used to encrypt short messages, like one-time passwords.
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        private byte[] EncryptAsymmetric(byte[] message) => _pri.Encrypt(message, RSAEncryptionPadding.Pkcs1);

        /// <summary>
        /// This method will likely throw an exception if the message is longer than 200-ish bytes.
        /// It is only used to decrypt short messages, like one-time passwords.
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        private byte[] DecryptAsymmetric(byte[] message) => _pri.Decrypt(message, RSAEncryptionPadding.Pkcs1);

        /// <summary>
        /// Encrypt a message using the public key.
        /// NOTE: The decrypting party must use this library's protocol to decrypt the message.
        /// The protocol is:
        /// (1) RSA-encrypt a random key of 32-bytes (256 bits).
        /// (2) Write the length of this key as Int32.
        /// (3) Write the encrypted key.
        /// (4) Write the symmetric-encrypted bytes of the message.
        /// To summarize this protocol, the cipher returned is a byte array containing the asymmetric-encrypted key plus the symmetric-encrypted message.
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] message)
        {
            // _pri.Encrypt() (backed by RSA 2048) can only encrypt a message that is 245 bytes or less; an inherent constraint of asymmetric cryptography.
            // Maybe longer bit spaces (e.g. 4096) can encrypt longer messages, but they all will be limited to under 1KB.
            // Your document will be longer. To get around this limitation, you asymmetric encrypt a short one-time password (random bytes) and use that to
            // symmetrically encrypt your message, since symmetric encryption has no message length limit.

            // So let's create a one-time key:
            var symmetricKey = Bytes.RandomBytesSecure(32); // 256-bit one-time key.
            var encryptedKey = EncryptAsymmetric(symmetricKey);

            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write(encryptedKey.Length);
                bw.Write(encryptedKey);
                bw.Write(Symmetric.Encrypt(message, symmetricKey));
                return ms.ToArray();
            }
        }

        /// <summary>
        /// Encrypt a string into a base-64 cipher.
        /// </summary>
        /// <param name="message">An string; e.g. JSON.</param>
        /// <returns>A base-64 encrypted string.</returns>
        public string Encrypt(string message) => Encrypt(message.ToBytes()).ToBase64();


        /// <summary>
        /// Decrypt a message using the private key.
        /// </summary>
        /// <param name="cipher">The encrypted bytes of an array of bytes.</param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] cipher)
        {
            using (var ms = new MemoryStream(cipher))
            using (var br = new BinaryReader(ms))
            {
                var encryptedKeyLength = br.ReadInt32();
                var encryptedKey = br.ReadBytes(encryptedKeyLength);
                var symmetricKey = DecryptAsymmetric(encryptedKey);
                var encryptedMessage = ms.ReadAllBytes();
                return Symmetric.Decrypt(encryptedMessage, symmetricKey);
            }
        }

        /// <summary>
        /// Decrypt a base-64 encrypted message string.
        /// </summary>
        /// <param name="cipher">The base-64 string that represents the encrypted message.</param>
        /// <returns></returns>
        public string Decrypt(string cipher) => Decrypt(cipher.FromBase64()).String();

        #region PEM Files
        /* A PEM file is a Base64-encoded ASN.1 (BER) that is enclosed in a BEGIN and END header string.*/

        /// <summary>
        /// For PEM files that contain the PRIVATE KEY, this converts those bytes into an RSAParameters object,
        /// which can then be attached to a certificate to allow decryption and signing.
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        static RSAParameters PemToParameters(byte[] bytes)
        {
            using (var ms = new MemoryStream(bytes))
            {
                var rsaParameters = new RSAParameters();
                using (var br = new BinaryReader(ms))
                {
                    var s1 = br.AsnReadTlv();
                    s1.tag.AssertEquals(0x30); // SEQUENCE
                    var s2 = s1.value.AsnReadTlv(); // INTEGER
                    var s3 = s1.value.AsnReadTlv(); // SEQUENCE
                    var s4 = s3.value.AsnReadTlv(); // OID
                    var s5 = s3.value.AsnReadTlv(); // NULL
                    var s6 = s1.value.AsnReadTlv(); // OCTET STRING
                    var s7 = s6.value.AsnReadTlv(); // SEQUENCE
                    s7.value.AsnReadTlv(); // INTEGER

                    rsaParameters.Modulus = s7.value.AsnReadTlv().bytes;
                    rsaParameters.Exponent = s7.value.AsnReadTlv().bytes;
                    rsaParameters.D = s7.value.AsnReadTlv().bytes; // Private Exponent
                    rsaParameters.P = s7.value.AsnReadTlv().bytes; // Prime1
                    rsaParameters.Q = s7.value.AsnReadTlv().bytes; // Prime2
                    rsaParameters.DP = s7.value.AsnReadTlv().bytes; // Exponent1
                    rsaParameters.DQ = s7.value.AsnReadTlv().bytes; // Exponent2
                    rsaParameters.InverseQ = s7.value.AsnReadTlv().bytes; // Coefficient

                    // Not sure why these byte array are prefixed with 00, but we need to remove it; else we get "Bad Data" error.
                    // See https://stackoverflow.com/questions/26551116/rsaprovider-importparameters-bad-data-for-some-special-rsa-private-keys
                    rsaParameters.P = rsaParameters.P.Drop(1);
                    rsaParameters.Q = rsaParameters.Q.Drop(1);
                    rsaParameters.Modulus = rsaParameters.Modulus.Drop(1);

                    return rsaParameters;
                }
            }
        }

        #endregion
    }
}
