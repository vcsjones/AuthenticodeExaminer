using System;
using System.Collections.Generic;
using System.Linq;

namespace AuthenticodeExaminer
{
    public static class SignatureExtensions
    {
        public static ISignature GetTimestampSignature(this ISignature signature)
        {
            var timestamps = signature.VisitAll(SignatureKind.AnyCounterSignature, false).ToArray();
            if (timestamps.Length == 0)
            {
                return null;
            }
            if (timestamps.Length > 1)
            {
                throw new InvalidOperationException("Signature contains multiple counter signers.");
            }
            return timestamps[0];
        }

        public static PublisherInformation GetPublisherInformation(this ISignature signature)
        {
            if ((signature.Kind & SignatureKind.AnySignature) == 0)
            {
                return null;
            }
            PublisherInformation info = null;
            foreach (var attribute in signature.SignedAttributes)
            {
                if (attribute.Oid.Value == KnownOids.OpusInfo)
                {
                    info = new PublisherInformation(attribute.Values[0]);
                    break;
                }
            }
            return info;
        }

        public static DateTimeOffset? GetTimestampSigningTime(this ISignature signature)
        {
            if (signature.Kind == SignatureKind.AuthenticodeTimestamp)
            {
                foreach (var attribute in signature.SignedAttributes)
                {
                    if (attribute.Oid.Value == KnownOids.SigningTime && attribute.Values.Count > 0)
                    {
                        return TimestampDecoding.DecodeAuthenticodeTimestamp(attribute.Values[0]);
                    }
                }
            }
            else if (signature.Kind == SignatureKind.Rfc3161Timestamp)
            {
                var content = signature.Content;
                return TimestampDecoding.DecodeRfc3161(content);
            }
            return null;
        }

        internal static IEnumerable<ISignature> VisitAll(this ISignature signature, SignatureKind kind, bool deep)
        {
            foreach (var nested in signature.GetNestedSignatures())
            {
                if ((nested.Kind & kind) > 0)
                {
                    yield return nested;
                    foreach (var nestVisit in nested.VisitAll(kind, deep))
                    {
                        yield return nestVisit;
                    }
                }
                else if (deep)
                {
                    foreach (var nestVisit in nested.VisitAll(kind, deep))
                    {
                        yield return nestVisit;
                    }
                }
            }
        }

        internal static IEnumerable<ISignature> VisitAll(this IReadOnlyList<ISignature> signatures, SignatureKind kind, bool deep)
        {
            foreach (var signature in signatures)
            {
                if ((signature.Kind & kind) > 0)
                {
                    yield return signature;
                }
                foreach (var nested in VisitAll(signature, kind, deep))
                {
                    yield return nested;
                }
            }
        }
    }
}
