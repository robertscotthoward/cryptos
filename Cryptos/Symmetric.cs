using System.Security.Cryptography;

namespace Cryptos
{
    /// <summary>
    /// This is a very simple, convenient implementation of AES-256 (i.e. Rijndael 256)
    /// </summary>
    /// <remarks>
    /// USAGE:
    /// <code>
    /// var cipher = Symmetric.Encrypt("Attack at dawn!", "Secret123");
    /// var message = Symmetric.Decrypt(cipher, "Secret123");
    /// </code>
    /// </remarks>
    /// <author>Robert Howard</author>
    public class Symmetric
    {
        /// <summary>
        /// Using a string key (e.g. a password), encrypt a message (e.g. JSON) into a base-64 encoded string.
        /// </summary>
        /// <param name="message">A string message (e.g. JSON) that you want to encrypt.</param>
        /// <param name="key">A string password.</param>
        /// <returns>A Base64-encoded string.</returns>
        public static string Encrypt(string message, string key) => Encrypt(message.ToBytes(), key.ToBytes()).ToBase64();

        /// <summary>
        /// Encrypt using AES-256.
        /// </summary>
        /// <param name="message">An array of bytes to be encrypted.</param>
        /// <param name="key">An array of bytes that serves as a symmetric key.</param>
        /// <returns>An array of encrypted bytes.</returns>
        public static byte[] Encrypt(byte[] message, byte[] key)
        {
            var aes = new AesCryptoServiceProvider { BlockSize = 128 };
            var K = key.ToSha256().Take(32); // The 32 is what makes this AES-256
            var T = aes.CreateEncryptor(K, K.Take(16));
            return T.TransformFinalBlock(message, 0, message.Length);
        }

        /// <summary>
        /// Using the private key, decrypt the cipher text returned from calling the Encrypt() method.
        /// </summary>
        /// <param name="cipher">The Base64-encoded cipher string returned from calling the Encrypt() method.</param>
        /// <param name="key">The password.</param>
        /// <returns>The message passed into the Encrypt() method.</returns>
        public static string Decrypt(string cipher, string key) => Decrypt(cipher.FromBase64(), key.ToBytes()).String();

        /// <summary>
        /// Using the private key, decrypt the cipher text returned from calling the Encrypt() method.
        /// </summary>
        /// <param name="cipher">The cipher returned from calling the Encrypt() method.</param>
        /// <param name="key">The encoded password.</param>
        /// <returns>The message passed into the Encrypt() method.</returns>
        public static byte[] Decrypt(byte[] cipher, byte[] key)
        {
            var aes = new AesCryptoServiceProvider { BlockSize = 128 };
            var K = key.ToSha256().Take(32); // The 32 is what makes this AES-256
            var T = aes.CreateDecryptor(K, K.Take(16));
            return T.TransformFinalBlock(cipher, 0, cipher.Length);
        }
    }
}
