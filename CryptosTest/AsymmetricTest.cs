using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using Cryptos;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptosTest
{
    [TestClass]
    public class AsymmetricTest
    {
        string signatureBase64 = "lkH0c5QXL04I2+EBLcfBlQdavDfC8usaEIcBZjqlnDyG6ugMmsE/0vjw3jA7h9BYLDAgAu+MkYuQfPlSQbA8kkBlA87l75HaHXxfaSJtoUX+scNqtc3kyEaEO2s5N9vxJVkCOpceYVRsAfuEqzAvZrEVbQAcMkcjVkHtE9bp9BCimQuziqXZA94JHtE8M1JkFv+Vy4JxIErHJYcq/bjuuPthEPM5TPlNAvHlj31HL6wkfl0r7k4AQedloVk1B9ejAyysKOcui5+gWB0ODg3EV43BzNeLIPoeydQ2rvg8d85YI3S1g8ZBAXKdOTowHJFAeCcZs9jE02i2j3t7za1eGA==";
        string message = "Attack at dawn!";
        private byte[] bytes = {0x25, 0x9F, 0xB3};
        string password = "hello"; // The password to the pfx file.
        string path = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

        [TestMethod]
        public void EncryptAndSignUsingPfxTest()
        {
            var rsa = new Asymmetric(Path.Join(path, @"Data\certificate.pfx"), password);

            // EXAMPLE WITH STRING
            var signature = rsa.Sign(message);
            Assert.IsTrue(rsa.Verify(message, signature));
            var cipher = rsa.Encrypt(message);
            Assert.AreEqual(message, rsa.Decrypt(cipher));

            // CONDENSED EXAMPLE WITH BYTES
            Assert.IsTrue(rsa.Verify(message, rsa.Sign(message)));
            Assert.AreEqual(message, rsa.Decrypt(rsa.Encrypt(message)));
        }

        [TestMethod]
        public void VerifyUsingPublicPemTest()
        {
            // Create a signature with the PFX file.
            var signature = new Asymmetric(Path.Join(path, @"Data\certificate.pfx"), password).Sign(message.ToBytes());

            // Use the PEM certificate to verify the signature.
            var pem = File.ReadAllText(Path.Join(path, @"Data\certificate.pem"));
            var rsa = Asymmetric.FromPem(pem);
            Assert.IsTrue(rsa.Verify(message.ToBytes(), signature));
            Assert.IsTrue(rsa.Verify(message.ToBytes(), signatureBase64.FromBase64()));

            // We should not be allowed to sign with just a public key.
            Assert.ThrowsException<Exception>(() => { rsa.Sign(message.ToBytes()); });
        }

        [TestMethod]
        public void EncryptWithPrivatePemTest()
        {
            var pem = File.ReadAllText(Path.Join(path, @"Data\certificate.pem")) + File.ReadAllText(Path.Join(path, @"Data\private.pem"));
            var rsa = Asymmetric.FromPem(pem);

            var cipher = rsa.Encrypt("Attack at dawn!");
            Assert.AreEqual("Attack at dawn!", rsa.Decrypt(cipher));

        }
    }
}
