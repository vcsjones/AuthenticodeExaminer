using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticodeExaminer
{
    /// <summary>
    /// An interface for low-level information about Authenticode signature.
    /// </summary>
    public interface ICmsSignature
    {
        /// <summary>
        /// Gets the hashing digest algorithm of the signature.
        /// </summary>
        Oid DigestAlgorithm { get; }

        /// <summary>
        /// Gets the signing algorithm of the signature.
        /// </summary>
        Oid HashEncryptionAlgorithm { get; }

        /// <summary>
        /// Provides a list of unsigned, or unathenticated, attributes in the current signature.
        /// </summary>
        IReadOnlyList<CryptographicAttributeObject> UnsignedAttributes { get; }

        /// <summary>
        /// Provides a list of signed, or authenticated, attributes in the current signature.
        /// </summary>
        IReadOnlyList<CryptographicAttributeObject> SignedAttributes { get; }

        /// <summary>
        /// Gets the X509 certificate used in the signature.
        /// </summary>
        X509Certificate2 Certificate { get; }
        
        /// <summary>
        /// Gets a list of sub-signatures, such as nested signatures or counter signatures.
        /// </summary>
        /// <returns>A read only list of immediate nested signatures.</returns>
        IReadOnlyList<ICmsSignature> GetNestedSignatures();

        /// <summary>
        /// Gets the kind of the signature. For more details, see <see cref="SignatureKind"/>.
        /// </summary>
        SignatureKind Kind { get; }

        /// <summary>
        /// Gets a list of additional certificates in the signature used to assist in chain
        /// building to the <see cref="Certificate"/>.
        /// </summary>
        X509Certificate2Collection AdditionalCertificates { get; }

        /// <summary>
        /// Gets a <see cref="HashAlgorithmName"/> representation of the <see cref="DigestAlgorithm"/>.
        /// </summary>
        HashAlgorithmName DigestAlgorithmName { get; }

        /// <summary>
        /// Provides the raw value of the content of the signature.
        /// </summary>
        byte[] Content { get;  }

        /// <summary>
        /// Get the serial number of the certificate used to sign the signature.
        /// </summary>
        byte[] SerialNumber { get; }
    }
}
