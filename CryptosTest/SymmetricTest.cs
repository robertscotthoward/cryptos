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
        }
    }
}
