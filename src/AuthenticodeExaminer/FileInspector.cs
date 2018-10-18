using System.Collections.Generic;

namespace AuthenticodeExaminer
{
    /// <summary>
    /// Inspects a file for Authenticode signatures.
    /// </summary>
    public class FileInspector
    {
        private readonly string _filePath;

        /// <summary>
        /// Creates a new instance of <see cref="FileInspector"/>.
        /// </summary>
        /// <param name="filePath">The path to the file to inspect.</param>
        public FileInspector(string filePath)
        {
            _filePath = filePath;
        }

        /// <summary>
        /// Checks the file for a complete Authenticode signature.
        /// </summary>
        /// <param name="revocationChecking">Indicates how X509 certificate revocation checking should be performed.</param>
        /// <returns>
        /// Returns <see cref="SignatureCheckResult.Valid"/> if the file is correctly signed. Otherwise,
        /// returns the failure.
        /// </returns>
        public SignatureCheckResult Validate(RevocationChecking revocationChecking = RevocationChecking.Offline)
        {
            var result = FileSignatureVerifier.IsFileSignatureValid(_filePath, revocationChecking);
            return (SignatureCheckResult)result;
        }

        /// <summary>
        /// Gets an enumeration of Authenticode signatures for the file.
        /// </summary>
        /// <returns>An enumeration of signatures.</returns>
        public IEnumerable<AuthenticodeSignature> GetSignatures()
        {
            var signatures = SignatureTreeInspector.Extract(_filePath);
            var allSignatures = signatures.VisitAll(SignatureKind.AnySignature, true);
            foreach(var signature in allSignatures)
            {
                yield return new AuthenticodeSignature(signature);
            }
        }
    }
}
