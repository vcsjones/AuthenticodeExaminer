namespace AuthenticodeExaminer
{
    /// <summary>
    /// Indicates how revocation checking of the signing certificate should be performed when
    /// authenticating an Authenticode signature using <see cref="FileSignatureVerifier.IsFileSignatureValid(string, RevocationChecking)"/>.
    /// </summary>
    public enum RevocationChecking
    {
        /// <summary>
        /// Indicates that no revocation checking should be performed.
        /// </summary>
        None,

        /// <summary>
        /// Indicates that offline revocation checking should be performed, and contacting the Certificate Authority
        /// for a CRL or OCSP response should not be done.
        /// </summary>
        Offline,

        /// <summary>
        /// Indicates that offline revocation checking should be performed, and contacting the Certificate Authority
        /// for a CRL or OCSP response should be done.
        /// </summary>
        Online
    }
}
