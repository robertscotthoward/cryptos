using Cryptos;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptosTest
{
    [TestClass]
    public class SymmetricTest
    {
        [TestMethod]
        public void EncryptTest()
        {
            var message = "Attack at dawn!";
            var password = "Shhhhh!";

            // Encrypt the message using our password to get a cipher text
            var cipher = Symmetric.Encrypt(message, password);

            Assert.AreEqual("i5gZtA6bIKXixFYTtalLxQ==", cipher);

            // Decode the cipher text using the same password to get the original message
            Assert.AreEqual(message, Symmetric.Decrypt(cipher, password));

            // CONDENSED EXAMPLE WITH BYTES
            byte[] messageBytes = { 0x25, 0x9F, 0xB3 };
            byte[] passwordBytes = { 0x12, 0x34, 0x56, 0x78 };
            Assert.AreEqual(messageBytes.ToBase64(), Symmetric.Decrypt(Symmetric.Encrypt(messageBytes, passwordBytes), passwordBytes).ToBase64());

        }
    }
}
