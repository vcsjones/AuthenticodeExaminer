using System.IO;
using System.Security.Cryptography;
using Xunit;

namespace AuthenticodeExaminer.Tests
{
    public static class SignatureTreeInspectorTests
    {
        private static readonly string _path = Path.Combine("inputs", "AuthenticodeExaminer-good.dl_");

        [Fact]
        public static void ShouldExtractSignatureDetails()
        {
            var extract = SignatureTreeInspector.Extract(_path);
            var root = Assert.Single(extract);
            Assert.NotNull(root);
            Assert.Equal(SignatureKind.Signature, root.Kind);
            Assert.Equal(HashAlgorithmName.SHA256, root.DigestAlgorithmName);
            Assert.Equal("CN=Kevin Jones, O=Kevin Jones, L=Alexandria, S=VA, C=US", root.Certificate.Subject);
            Assert.Equal("1.2.840.113549.1.1.1", root.HashEncryptionAlgorithm.Value); //pkcs-1 rsaEncryption

            var timestamp = Assert.Single(root.VisitAll(SignatureKind.Rfc3161Timestamp, false));
            Assert.NotNull(timestamp);
            Assert.Equal(SignatureKind.Rfc3161Timestamp, timestamp.Kind);
            Assert.Equal(HashAlgorithmName.SHA256, timestamp.DigestAlgorithmName);
            Assert.Equal("CN=DigiCert SHA2 Timestamp Responder, O=DigiCert, C=US", timestamp.Certificate.Subject);
            Assert.Equal("1.2.840.113549.1.1.1", timestamp.HashEncryptionAlgorithm.Value); //pkcs-1 rsaEncryption
        }
    }
}
