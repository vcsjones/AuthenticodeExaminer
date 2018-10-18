using System.Collections.Generic;

namespace AuthenticodeExaminer
{
    /// <summary>
    /// Indicates the result when validating an Authenticode signed file.
    /// </summary>
    public enum SignatureCheckResult : int
    {
        Valid = 0,
        NoSignature = unchecked((int)0x800b0100), //TRUST_E_NOSIGNATURE
        BadDigest = unchecked((int)0x80096010), //TRUST_E_BAD_DIGEST
        UnknownProvider = unchecked((int)0x800b0001), //TRUST_E_PROVIDER_UNKNOWN
        UntrustedRoot = unchecked((int)0x800b0109), //CERT_E_UNTRUSTEDROOT
        ExplicitDistrust = unchecked((int)0x800b0111), //TRUST_E_EXPLICIT_DISTRUST
    }


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
        public IEnumerable<ISignature> GetSignatures()
        {
            var signatures = SignatureTreeInspector.Extract(_filePath);
            return signatures.VisitAll(SignatureKind.AnySignature, true);
        }
    }
}
