namespace AuthenticodeExaminer
{
    /// <summary>
    /// Indicates the result when validating an Authenticode signed file.
    /// </summary>
    public enum SignatureCheckResult : int
    {
        /// <summary>
        /// The signature is valid and trusted.
        /// </summary>
        Valid = 0,

        /// <summary>
        /// The file does is not Authenticode signed.
        /// </summary>
        NoSignature = unchecked((int)0x800b0100), //TRUST_E_NOSIGNATURE

        /// <summary>
        /// The file is signed, however the signed hash does not match the computed hash.
        /// </summary>
        BadDigest = unchecked((int)0x80096010), //TRUST_E_BAD_DIGEST

        /// <summary>
        /// The file has a signature, but a provider could not be found to verify its
        /// authenticity.
        /// </summary>
        UnknownProvider = unchecked((int)0x800b0001), //TRUST_E_PROVIDER_UNKNOWN

        /// <summary>
        /// The file is signed with an untrusted certificate.
        /// </summary>
        UntrustedRoot = unchecked((int)0x800b0109), //CERT_E_UNTRUSTEDROOT

        /// <summary>
        /// The file is signed, however is explicitly distrusted on this system.
        /// </summary>
        ExplicitDistrust = unchecked((int)0x800b0111), //TRUST_E_EXPLICIT_DISTRUST
    }
}
