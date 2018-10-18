using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace AuthenticodeExaminer
{
    /// <summary>
    /// A class that represents an Authenticode signature.
    /// </summary>
    public sealed class AuthenticodeSignature
    {
        private readonly ICmsSignature _cmsSignature;
        private IReadOnlyList<TimestampSignature> _timestampSignatures;
        private PublisherInformation _publisherInformation;

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
        public IReadOnlyList<TimestampSignature> TimestampSignatures
        {
            get
            {
                if (_timestampSignatures == null)
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
                    Interlocked.CompareExchange(ref _timestampSignatures, list, null);
                }
                return _timestampSignatures;
            }
        }

        /// <summary>
        /// Gets the signer-provided publisher information on the Authenticode signature.
        /// See <see cref="AuthenticodeExaminer.PublisherInformation"/> for additional details.
        /// </summary>
        public PublisherInformation PublisherInformation
        {
            get
            {
                if (_publisherInformation == null)
                {
                    PublisherInformation publisherInformation = null;
                    foreach (var attribute in _cmsSignature.SignedAttributes)
                    {
                        if (attribute.Oid.Value == KnownOids.OpusInfo && attribute.Values.Count > 0)
                        {
                            publisherInformation = new PublisherInformation(attribute.Values[0]);
                        }
                    }
                    Interlocked.CompareExchange(ref _publisherInformation, publisherInformation ?? new PublisherInformation(), null);
                }
                return _publisherInformation;
            }
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
        public DateTimeOffset? TimestampDateTime { get; protected set; }

        private protected TimestampSignature(ICmsSignature cmsSignature)
        {
            _cmsSignature = cmsSignature;
        }

        internal class AuthenticodeTimestampSignature : TimestampSignature
        {

            public AuthenticodeTimestampSignature(AuthenticodeTimestampCmsSignature authenticodeCmsSignature) : base(authenticodeCmsSignature)
            {
                foreach (var attribute in authenticodeCmsSignature.SignedAttributes)
                {
                    if (attribute.Oid.Value == KnownOids.SigningTime && attribute.Values.Count > 0)
                    {
                        TimestampDateTime = TimestampDecoding.DecodeAuthenticodeTimestamp(attribute.Values[0]);
                    }
                }
            }
        }

        internal class RFC3161TimestampSignature : TimestampSignature
        {

            public RFC3161TimestampSignature(CmsSignature rfc3161Signature) : base(rfc3161Signature)
            {
                var content = rfc3161Signature.Content;
                TimestampDateTime = TimestampDecoding.DecodeRfc3161(content);
            }
        }
    }
}
