using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Cryptos
{
    /// <summary>
    /// Some convenient extension methods for working with byte arrays among other things.
    /// </summary>
    /// <author>Robert Howard</author>
    public static class Bytes
    {
        public static byte[] ToMd5(this byte[] bytes) => new MD5CryptoServiceProvider().ComputeHash(bytes);
        public static byte[] ToSha1(this byte[] bytes) => new SHA1CryptoServiceProvider().ComputeHash(bytes);
        public static byte[] ToSha256(this byte[] bytes) => new SHA384CryptoServiceProvider().ComputeHash(bytes);
        public static string ToBase64(this byte[] bytes) => Convert.ToBase64String(bytes ?? new byte[0]);

        /// <summary>
        /// Return the head of a byte array; i.e. the first <paramref name="length"/> bytes in the array.
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public static byte[] Take(this byte[] bytes, int length)
        {
            byte[] b;
            int l;
            if (length < 0)
            {
                length = -length;
                l = Math.Min(bytes.Length, length);
                b = new byte[l];
                Array.Copy(bytes, bytes.Length - l, b, 0, l);
                return b;
            }

            l = Math.Min(bytes.Length, length);
            b = new byte[l];
            Array.Copy(bytes, 0, b, 0, l);
            return b;
        }

        /// <summary>
        /// Return the tail end of a byte array.
        /// </summary>
        /// <param name="bytes">The input byte array.</param>
        /// <param name="length">The number of bytes to skip over before returning the remaining number of bytes.
        /// If negative, then return that number of bytes from the end of the array.</param>
        /// <returns></returns>
        public static byte[] Skip(this byte[] bytes, int length)
        {
            byte[] b;
            int l;
            if (length < 0)
            {
                l = -length;
                if (l < 0) return new byte[0];
                if (l > bytes.Length) return bytes;
                l = Math.Min(bytes.Length, bytes.Length - l);
                b = new byte[l];
                Array.Copy(bytes, 0, b, 0, l);
                return b;
            }

            l = bytes.Length - length;
            if (l < 0) return new byte[0]; 
            b = new byte[l];
            Array.Copy(bytes, bytes.Length - l, b, 0, l);
            return b;
        }

        public static byte[] FromBase64(this string s) => Convert.FromBase64String(s.PadBase64() ?? "");
        public static byte[] ToBytes(this string s) => Encoding.UTF8.GetBytes(s);

        /// <summary>
        /// Some Base64-encoders forget to pad their encoded string, which causes the Convert.FromBase64String to throw a FormatException. This corrects those cases.
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        public static string PadBase64(this string s)
        {
            s = s.RemoveWhiteSpace();
            while (s.Length % 4 != 0) s += "=";
            return s;
        }

        public static string String(this byte[] bytes) => Encoding.UTF8.GetString(bytes);

        public static readonly string HexBytes = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";
        /// <summary>
        ///     Return the two-character hexadecimal encoding of a byte; i.e. 00 to FF.
        /// </summary>
        /// <param name="b"></param>
        /// <returns></returns>
        public static string ToHex(byte b) => HexBytes.Substring(b << 1, 2);

        public static string ToHex(this byte[] bytes)
        {
            bytes = bytes ?? new byte[0];
            var s = new StringBuilder();
            foreach (var t in bytes)
                s.AppendFormat(ToHex(t));
            return s.ToString();
        }

        /// <summary>
        /// Convert a hex string to a byte array.
        /// </summary>
        /// <param name="hex"></param>
        /// <returns></returns>
        public static byte[] FromHex(this string hex)
        {
            hex = hex.RemoveWhiteSpace();
            var ms = new MemoryStream();
            for (var i = 0; i < hex.Length; i += 2)
                ms.WriteByte(Convert.ToByte(hex.Substring(i, 2), 16));
            return ms.ToArray();
        }

        /// <summary>
        /// Return one or more cryptographically secure random bytes, typically used for one-time pads.
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public static byte[] RandomBytesSecure(int length)
        {
            var bytes = new byte[length];
            new RNGCryptoServiceProvider().GetBytes(bytes);
            return bytes;
        }

        /// <summary>
        /// Read all remaining bytes in a stream.
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        public static byte[] ReadAllBytes(this Stream reader)
        {
            using (var ms = new MemoryStream())
            {
                byte[] bytes = new byte[4096];
                int count;
                while ((count = reader.Read(bytes, 0, bytes.Length)) != 0)
                    ms.Write(bytes, 0, count);
                return ms.ToArray();
            }
        }

        public static byte[] Drop(this byte[] bytes, int n)
        {
            var a = new byte[bytes.Length - n];
            Array.Copy(bytes, n, a, 0, a.Length);
            return a;
        }

        /// <summary>
        /// Remove all whitespace, including CR and LF.
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        public static string RemoveWhiteSpace(this string s) => Regex.Replace(s, @"\s+", "");

        public static string Between(this string s, string a, string b)
        {
            int i;
            if (!string.IsNullOrEmpty(a))
            {
                i = s.IndexOf(a, StringComparison.Ordinal);
                if (i < 0) return "";
                s = s.Substring(i + a.Length);
            }

            if (!string.IsNullOrEmpty(b))
            {
                i = s.IndexOf(b, StringComparison.Ordinal);
                if (i < 0) return "";
                s = s.Substring(0, i);
            }

            return s;
        }

        public static T AssertEquals<T>(this T t, object u)
        {
            if (t.ToString() != u.ToString()) throw new Exception($"Expected '{t}' but got '{u}'");
            return t;
        }

        #region ASN.1
        
        public static (byte tag, int length, byte[] bytes, BinaryReader value) AsnReadTlv(this BinaryReader r)
        {
            var t = r.ReadByte();
            var l = r.AsnReadLength();
            var v = r.ReadBytes(l);
            return (t, l, v, new BinaryReader(new MemoryStream(v)));
        }

        public static int AsnReadLength(this BinaryReader r)
        {
            var b = r.ReadByte();
            if (b < 128) return b;
            var l = b & 0x7F;
            var bytes = r.ReadBytes(l);
            return bytes.Aggregate(0, (current, x) => (current << 8) + x);
        }

        /// <summary>
        /// Concatenate two similar arrays.
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static T[] Append<T>(this T[] a, T[] b)
        {
            var c = new T[a.Length + b.Length];
            a.CopyTo(c, 0);
            b.CopyTo(c, a.Length);
            return c;
        }
        #endregion
    }

}