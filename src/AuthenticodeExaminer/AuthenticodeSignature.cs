using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticodeExaminer
{
    /// <summary>
    /// A class that represents an Authenticode signature.
    /// </summary>
    public sealed class AuthenticodeSignature
    {
        private readonly ICmsSignature _cmsSignature;

        internal AuthenticodeSignature(ICmsSignature cmsSignature)
        {
            if ((cmsSignature.Kind & SignatureKind.AnySignature) == 0)
            {
                throw new ArgumentException("The signature must be a root or nested signature.", nameof(cmsSignature));
            }
            _cmsSignature = cmsSignature;
        }

        /// <summary>
        /// Gets the X509 certificate used in the signature.
        /// </summary>
        public X509Certificate2 SigningCertificate => _cmsSignature.Certificate;

        /// <summary>
        /// Gets a list of additional certificates provided by the signer in the signature used to assist in chain
        /// building for the <see cref="SigningCertificate"/>.
        /// </summary>
        public X509Certificate2Collection AdditionalCertificates => _cmsSignature.AdditionalCertificates;

        /// <summary>
        /// Provides the raw content of the signature, or null.
        /// </summary>
        public byte[] Contents => _cmsSignature.Content;

        /// <summary>
        /// Gets the algorithm used to hash the subject that is signed.
        /// </summary>
        public HashAlgorithmName DigestAlgorithmName => _cmsSignature.DigestAlgorithmName;

        /// <summary>
        /// Gets a list of counter timestamp signers.
        /// </summary>
        /// <returns>A list of <see cref="TimestampSignature"/>.</returns>
        public IReadOnlyList<TimestampSignature> GetTimestampSignatures()
        {
            var list = new List<TimestampSignature>();
            var timestamps = _cmsSignature.VisitAll(SignatureKind.AnyCounterSignature, false);
            foreach (var timestamp in timestamps)
            {
                switch (timestamp)
                {
                    case AuthenticodeTimestampCmsSignature legacy:
                        list.Add(new TimestampSignature.AuthenticodeTimestampSignature(legacy));
                        break;
                    case CmsSignature rfc3161 when rfc3161.Kind == SignatureKind.Rfc3161Timestamp:
                        list.Add(new TimestampSignature.RFC3161TimestampSignature(rfc3161));
                        break;
                }
            }
            return list;
        }

        /// <summary>
        /// Gets the signer-provided publisher information on the Authenticode signature.
        /// See <see cref="PublisherInformation"/> for additional details.
        /// </summary>
        /// <returns>
        /// Returns a <see cref="PublisherInformation"/>, or null if the publisher information
        /// is absent entirely.
        /// </returns>
        /// <remarks>Microsoft's <c>signtool</c> always embeds a publisher information, even when
        /// omitted by the signer. When it is omitted, the properties in the publisher information
        /// are empty values.</remarks>
        public PublisherInformation GetPublisherInformation()
        {
            foreach (var attribute in _cmsSignature.SignedAttributes)
            {
                if (attribute.Oid.Value == KnownOids.OpusInfo && attribute.Values.Count > 0)
                {
                    return new PublisherInformation(attribute.Values[0]);
                }
            }
            return null;
        }
    }

    /// <summary>
    /// Represents a timestamp signature that has counter signed an Authenticode signature.
    /// </summary>
    public abstract class TimestampSignature
    {
        private readonly ICmsSignature _cmsSignature;

        /// <summary>
        /// Gets the X509 certificate used in the signature.
        /// </summary>
        public X509Certificate2 SigningCertificate => _cmsSignature.Certificate;

        /// <summary>
        /// Gets a list of additional certificates provided by the signer in the signature used to assist in chain
        /// building for the <see cref="SigningCertificate"/>.
        /// </summary>
        public X509Certificate2Collection AdditionalCertificates => _cmsSignature.AdditionalCertificates;

        /// <summary>
        /// Provides the raw content of the signature, or null.
        /// </summary>
        public byte[] Contents => _cmsSignature.Content;

        /// <summary>
        /// Gets the algorithm used to hash the subject that is signed.
        /// </summary>
        public HashAlgorithmName DigestAlgorithmName => _cmsSignature.DigestAlgorithmName;

        /// <summary>
        /// Gets a <c>DateTimeOffset</c> of the timestamp's value. This may be null if the timestamp
        /// could not be parsed correctly.
        /// </summary>
        public abstract DateTimeOffset? TimestampDateTime { get; }

        private protected TimestampSignature(ICmsSignature cmsSignature)
        {
            _cmsSignature = cmsSignature;
        }

        internal class AuthenticodeTimestampSignature : TimestampSignature
        {
            private readonly AuthenticodeTimestampCmsSignature _authenticodeCmsSignature;

            public AuthenticodeTimestampSignature(AuthenticodeTimestampCmsSignature authenticodeCmsSignature) : base(authenticodeCmsSignature)
            {
                _authenticodeCmsSignature = authenticodeCmsSignature;
            }

            public override DateTimeOffset? TimestampDateTime
            {
                get
                {
                    foreach (var attribute in _authenticodeCmsSignature.SignedAttributes)
                    {
                        if (attribute.Oid.Value == KnownOids.SigningTime && attribute.Values.Count > 0)
                        {
                            return TimestampDecoding.DecodeAuthenticodeTimestamp(attribute.Values[0]);
                        }
                    }
                    return null;
                }
            }
        }

        internal class RFC3161TimestampSignature : TimestampSignature
        {
            private readonly CmsSignature _rfc3161Signature;

            public RFC3161TimestampSignature(CmsSignature rfc3161Signature) : base(rfc3161Signature)
            {
                _rfc3161Signature = rfc3161Signature;
            }

            public override DateTimeOffset? TimestampDateTime
            {
                get
                {
                    var content = _rfc3161Signature.Content;
                    return TimestampDecoding.DecodeRfc3161(content);
                }
            }
        }
    }
}
