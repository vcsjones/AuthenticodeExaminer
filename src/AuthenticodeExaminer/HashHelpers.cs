using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AuthenticodeExaminer
{
    public static class HashHelpers
    {
        public static string GetHashForSignature(ISignature signature)
        {
            var digest = signature.SignatureDigest();
            var digestString = digest.Aggregate(new StringBuilder(), (acc, b) => acc.AppendFormat("{0:x2}", b)).ToString();
            return digestString;
        }

        public static string HexEncode(byte[] data)
        {
            return data.Aggregate(new StringBuilder(), (acc, b) => acc.AppendFormat("{0:x2}", b)).ToString();
        }

        public static string HexEncodeBigEndian(byte[] data)
        {
            return data.Aggregate(new StringBuilder(), (acc, b) => acc.Insert(0, string.Format("{0:x2}", b))).ToString();
        }
    }

    public static class SignerInfoExtensions
    {
        public static byte[] SignatureDigest(this ISignature signature)
        {
            return signature.SignedAttributes
                .Cast<CryptographicAttributeObject>()
                .FirstOrDefault(s => s.Oid.Value == KnownOids.MessageDigest)?.Values[0].RawData;
        }
    }
}
