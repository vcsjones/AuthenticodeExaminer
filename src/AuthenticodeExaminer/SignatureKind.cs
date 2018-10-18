using System;

namespace AuthenticodeExaminer
{
    /// <summary>
    /// A enumeration to indicate the kind of signature.
    /// </summary>
    [Flags]
    public enum SignatureKind
    {
        /// <summary>
        /// The signature is a nested, or appended signature to an existing signature.
        /// </summary>
        NestedSignature = 0x1,

        /// <summary>
        /// A root signature that is not contained in an existing signature.
        /// </summary>
        Signature = 0x2,
        
        /// <summary>
        /// A legacy Authenticode-style timestamp signature.
        /// </summary>
        AuthenticodeTimestamp = 0x4,

        /// <summary>
        /// An RFC3161 compliant timestamp signature.
        /// </summary>
        Rfc3161Timestamp = 0x8,
        
        /// <summary>
        /// A bitwise combination of any Authenticode signature.
        /// </summary>
        AnySignature = NestedSignature | Signature,

        /// <summary>
        /// A bitwise combination of any counter signature.
        /// </summary>
        AnyCounterSignature = AuthenticodeTimestamp | Rfc3161Timestamp,

        /// <summary>
        /// Any kind of signature.
        /// </summary>
        Any = AnySignature | AnyCounterSignature
    }
}
