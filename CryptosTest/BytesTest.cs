using Cryptos;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptosTest
{
    [TestClass]
    public class BytesTest
    {
        private string alphabet = "abcdefghijklmnopqrstuvwxyz";
        private string alphabet1 = @"

 abcdefg
hij k   lmn opqrstuvwxyz

";


        [TestMethod]
        public void Hashes()
        {
            Assert.AreEqual("C3FCD3D76192E4007DFB496CCA67E13B", alphabet.ToBytes().ToMd5().ToHex());
            Assert.AreEqual("32D10C7B8CF96570CA04CE37F2A19D84240D3A89", alphabet.ToBytes().ToSha1().ToHex());
            Assert.AreEqual("FEB67349DF3DB6F5924815D6C3DC133F091809213731FE5C7B5F4999E463479FF2877F5F2936FA63BB43784B12F3EBB4", alphabet.ToBytes().ToSha256().ToHex());
        }

        [TestMethod]
        public void Base64()
        {
            Assert.AreEqual("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=", alphabet.ToBytes().ToBase64());
            Assert.AreEqual(alphabet, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=".FromBase64().String());
            Assert.AreEqual(alphabet, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo".FromBase64().String());
            Assert.AreEqual(alphabet, alphabet.ToBytes().ToBase64().FromBase64().String());
        }

        [TestMethod]
        public void StringToBytes()
        {
            Assert.AreEqual("6162636465666768696A6B6C6D6E6F707172737475767778797A", alphabet.ToBytes().ToHex());
            Assert.AreEqual("", "".ToBytes().ToHex());
            Assert.AreEqual(alphabet, "6162636465666768696A6B6C6D6E6F707172737475767778797A".FromHex().String());
            Assert.AreEqual(alphabet, "6162636465666768696a6b6c6d6e6f707172737475767778797a".FromHex().String());
            Assert.AreEqual(alphabet, alphabet.ToBytes().String());
        }

        [TestMethod]
        public void ToHex()
        {
            Assert.AreEqual("123456FE", new byte[]{0x12, 0x34, 0x56, 0xFE}.ToHex());
        }

        [TestMethod]
        public void RemoveWhiteSpace()
        {
            Assert.AreEqual(alphabet, alphabet1.RemoveWhiteSpace());
        }


        [TestMethod]
        public void Between()
        {
            Assert.AreEqual("def", alphabet.Between("abc", "ghij"));
            Assert.AreEqual("ghi", alphabet.Between("f", "j"));
            
            Assert.AreEqual("jklmnopqrstuvwxyz", alphabet.Between("abcdefghi", null));
            Assert.AreEqual("jklmnopqrstuvwxyz", alphabet.Between("ghi", null));
            Assert.AreEqual("jklmnopqrstuvwxyz", alphabet.Between("ghi", ""));
            
            Assert.AreEqual("abcdefghijklmno", alphabet.Between("", "p"));
        }
    }
}
