using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticodeExaminer
{
    internal static class KnownOids
    {
        public static class X509Algorithms
        {
            public const string RSA = "1.2.840.113549.1.1.1";
            public const string Ecc = "1.2.840.10045.2.1";
        }

        public static class EccCurves
        {
            public const string EcdsaP256 = "1.2.840.10045.3.1.7";
            public const string EcdsaP384 = "1.3.132.0.34";
            public const string EcdsaP521 = "1.3.132.0.35";
        }


        public const string SHA1 = "1.3.14.3.2.26";
        public const string SHA256 = "2.16.840.1.101.3.4.2.1";
        public const string SHA384 = "2.16.840.1.101.3.4.2.2";
        public const string SHA512 = "2.16.840.1.101.3.4.2.3";
        public const string MD5 = "1.2.840.113549.2.5";
        public const string MD4 = "1.2.840.113549.2.4";
        public const string MD2 = "1.2.840.113549.2.2";

        public const string Rfc3161CounterSignature = "1.3.6.1.4.1.311.3.3.1";
        public const string AuthenticodeCounterSignature = "1.2.840.113549.1.9.6";
        public const string MessageDigest = "1.2.840.113549.1.9.4";
        public const string OpusInfo = "1.3.6.1.4.1.311.2.1.12";
        public const string CodeSigning = "1.3.6.1.5.5.7.3.3";
        public const string NestedSignatureOid = "1.3.6.1.4.1.311.2.4.1";
        public const string SealingSignature = "1.3.6.1.4.1.311.2.4.3";
        public const string SealingTimestamp = "1.3.6.1.4.1.311.2.4.4";
        public const string KeyId = "1.3.6.1.4.1.311.10.7.1";
        public const string SigningTime = "1.2.840.113549.1.9.5";


        public const string md5RSA = "1.2.840.113549.1.1.4";
        public const string sha1DSA = "1.2.840.10040.4.3";
        public const string sha1RSA = "1.2.840.113549.1.1.5";
        public const string sha256RSA = "1.2.840.113549.1.1.11";
        public const string sha384RSA = "1.2.840.113549.1.1.12";
        public const string sha512RSA = "1.2.840.113549.1.1.13";
        public const string sha1ECDSA = "1.2.840.10045.4.1";
        public const string sha256ECDSA = "1.2.840.10045.4.3.2";
        public const string sha384ECDSA = "1.2.840.10045.4.3.3";
        public const string sha512ECDSA = "1.2.840.10045.4.3.4";
    }
}
