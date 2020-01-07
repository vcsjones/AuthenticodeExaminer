using System.IO;
using Xunit;

namespace AuthenticodeExaminer.Tests
{
    public static class FileInspectorTests
    {
        [Fact]
        public static void ShouldValidateFileSuccessfully()
        {
            var inspector = new FileInspector(Path.Combine("inputs", "AuthenticodeExaminer-good.dl_"));
            var result = inspector.Validate(RevocationChecking.None);
            Assert.Equal(SignatureCheckResult.Valid, result);
        }

        [Fact]
        public static void ShouldCorrectlyReportUnsignedFile()
        {
            // Use the current DLL since it will never be signed.
            var inspector = new FileInspector(typeof(FileInspectorTests).Assembly.Location);
            var result = inspector.Validate(RevocationChecking.None);
            Assert.Equal(SignatureCheckResult.NoSignature, result);
        }

        [Fact]
        public static void ShouldCorrectlyReportBadFileSignature()
        {
            var inspector = new FileInspector(Path.Combine("inputs", "AuthenticodeExaminer-bad.dl_"));
            var result = inspector.Validate(RevocationChecking.None);
            Assert.Equal(SignatureCheckResult.BadDigest, result);
        }

        [Fact]
        public static void ShouldCorrectlyReportUnknownFileTypeForSubject()
        {
            var inspector = new FileInspector(Path.Combine("inputs", "wat.txt"));
            var result = inspector.Validate(RevocationChecking.None);
            Assert.Equal(SignatureCheckResult.UnknownSubject, result);
        }

        [Fact]
        public static void ShouldExtractSignatures()
        {
            var inspector = new FileInspector(Path.Combine("inputs", "AuthenticodeExaminer-good.dl_"));
            var signatures = inspector.GetSignatures();
            Assert.NotEmpty(signatures);
        }

        [Fact]
        public static void ShouldExtractSignaturesEvenForBadDigest()
        {
            var inspector = new FileInspector(Path.Combine("inputs", "AuthenticodeExaminer-bad.dl_"));
            var signatures = inspector.GetSignatures();
            Assert.NotEmpty(signatures);
        }
    }
}
