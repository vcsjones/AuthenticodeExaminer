using AuthenticodeExaminer.Interop;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Collections.Generic;

namespace AuthenticodeExaminer
{
    /// <summary>
    /// An abstract class for different signature implementations.
    /// </summary>
    public abstract class CmsSignatureBase : ICmsSignature
    {
        /// <inheritdoc/>
        public Oid? DigestAlgorithm { get; protected set; }
        /// <inheritdoc/>
        public Oid? HashEncryptionAlgorithm { get; protected set; }
        /// <inheritdoc/>
        public IReadOnlyList<CryptographicAttributeObject> UnsignedAttributes { get; protected set; } = Array.Empty<CryptographicAttributeObject>();
        /// <inheritdoc/>
        public IReadOnlyList<CryptographicAttributeObject> SignedAttributes { get; protected set; } = Array.Empty<CryptographicAttributeObject>();
        /// <inheritdoc/>
        public byte[] SerialNumber { get; protected set; } = Array.Empty<byte>();
        /// <inheritdoc/>
        public X509Certificate2? Certificate { get; protected set; }
        /// <inheritdoc/>
        public SignatureKind Kind { get; protected set; }
        /// <inheritdoc/>
        public X509Certificate2Collection AdditionalCertificates { get; protected set; } = new X509Certificate2Collection();
        /// <inheritdoc/>
        public byte[]? Content { get; protected set; }
        /// <inheritdoc/>
        public ReadOnlyMemory<byte> Signature { get; protected set; }
        /// <inheritdoc/>
        public HashAlgorithmName DigestAlgorithmName => DigestAlgorithm?.Value switch {
            KnownOids.MD5 => HashAlgorithmName.MD5,
            KnownOids.SHA1 => HashAlgorithmName.SHA1,
            KnownOids.SHA256 => HashAlgorithmName.SHA256,
            KnownOids.SHA384 => HashAlgorithmName.SHA384,
            KnownOids.SHA512 => HashAlgorithmName.SHA512,
            _ => default
        };

        internal byte[] ReadBlob(CRYPTOAPI_BLOB blob) => blob.AsSpan().ToArray();

        internal unsafe List<CryptographicAttributeObject> ReadAttributes(CRYPT_ATTRIBUTES attributes)
        {
            var collection = new List<CryptographicAttributeObject>();
            var attributeSize = Marshal.SizeOf<CRYPT_ATTRIBUTE>();
            var blobSize = Marshal.SizeOf<CRYPTOAPI_BLOB>();
            for (var i = 0; i < attributes.cAttr; i++)
            {
                var structure = Marshal.PtrToStructure<CRYPT_ATTRIBUTE>(attributes.rgAttr + (i * attributeSize));
                var asnValues = new AsnEncodedDataCollection();
                for (var j = 0; j < structure.cValue; j++)
                {
                    var blob = Marshal.PtrToStructure<CRYPTOAPI_BLOB>(structure.rgValue + j * blobSize);
                    asnValues.Add(new AsnEncodedData(structure.pszObjId, ReadBlob(blob)));
                }
                collection.Add(new CryptographicAttributeObject(new Oid(structure.pszObjId), asnValues));
            }
            return collection;
        }

        private protected X509Certificate2? FindCertificate(X509IssuerSerial issuerSerial, X509Certificate2Collection certificateCollection)
        {
            var byDN = certificateCollection.Find(X509FindType.FindByIssuerDistinguishedName, issuerSerial.IssuerName, false);
            if (byDN.Count < 1)
            {
                return null;
            }
            var bySerial = byDN.Find(X509FindType.FindBySerialNumber, issuerSerial.SerialNumber, false);
            if (bySerial.Count != 1)
            {
                return null;
            }
            return bySerial[0];
        }

        private protected X509Certificate2? FindCertificate(string keyId, X509Certificate2Collection certificateCollection)
        {
            var byKeyId = certificateCollection.Find(X509FindType.FindBySubjectKeyIdentifier, keyId, false);
            if (byKeyId.Count != 1)
            {
                return null;
            }
            return byKeyId[0];
        }

        private protected X509Certificate2Collection GetCertificatesFromMessage(CryptMsgSafeHandle handle)
        {
            var size = (uint)Marshal.SizeOf<uint>();
            var certs = new X509Certificate2Collection();
            uint certCount;
            using (var certCountLocalBuffer = LocalBufferSafeHandle.Alloc(size))
            {
                if (!Crypt32.CryptMsgGetParam(handle, CryptMsgParamType.CMSG_CERT_COUNT_PARAM, 0, certCountLocalBuffer, ref size))
                {
                    return certs;
                }
                certCount = unchecked((uint)Marshal.ReadInt32(certCountLocalBuffer.DangerousGetHandle(), 0));
            }
            if (certCount == 0)
            {
                return certs;
            }
            for (var i = 0u; i < certCount; i++)
            {
                uint certSize = 0;
                if (!Crypt32.CryptMsgGetParam(handle, CryptMsgParamType.CMSG_CERT_PARAM, i, LocalBufferSafeHandle.Zero, ref certSize))
                {
                    continue;
                }
                using (var certLocalBuffer = LocalBufferSafeHandle.Alloc(certSize))
                {
                    if (!Crypt32.CryptMsgGetParam(handle, CryptMsgParamType.CMSG_CERT_PARAM, i, certLocalBuffer, ref certSize))
                    {
                        continue;
                    }
                    var data = new byte[certSize];
                    Marshal.Copy(certLocalBuffer.DangerousGetHandle(), data, 0, data.Length);
                    var cert = new X509Certificate2(data);
                    certs.Add(cert);
                }
            }
            return certs;
        }

        /// <inheritdoc />
        public abstract IReadOnlyList<ICmsSignature> GetNestedSignatures();
    }

    /// <summary>
    /// A class representing a Authenticode timestamp signature.
    /// </summary>
    public sealed class AuthenticodeTimestampCmsSignature : CmsSignatureBase
    {
        /// <summary>
        /// Gets the signature that owns this timestamp signature.
        /// </summary>
        public ICmsSignature OwningSignature { get; }

        internal unsafe AuthenticodeTimestampCmsSignature(AsnEncodedData data, ICmsSignature owningSignature)
        {
            OwningSignature = owningSignature;
            Kind = SignatureKind.AuthenticodeTimestamp;
            AdditionalCertificates = owningSignature.AdditionalCertificates;
            fixed (byte* dataPtr = data.RawData)
            {
                uint size = 0;
                if (Crypt32.CryptDecodeObjectEx(EncodingType.PKCS_7_ASN_ENCODING | EncodingType.X509_ASN_ENCODING, (IntPtr)500, new IntPtr(dataPtr), (uint)data.RawData.Length, CryptDecodeFlags.CRYPT_DECODE_ALLOC_FLAG, IntPtr.Zero, out var localBuffer, ref size))
                {
                    using (localBuffer)
                    {
                        var signerInfo = Marshal.PtrToStructure<CMSG_SIGNER_INFO>(localBuffer.DangerousGetHandle());
                        Signature = ReadBlob(signerInfo.EncryptedHash);
                        DigestAlgorithm = new Oid(signerInfo.HashAlgorithm.pszObjId);
                        HashEncryptionAlgorithm = new Oid(signerInfo.HashEncryptionAlgorithm.pszObjId);
                        SerialNumber = ReadBlob(signerInfo.SerialNumber);
                        UnsignedAttributes = ReadAttributes(signerInfo.UnauthAttrs);
                        SignedAttributes = ReadAttributes(signerInfo.AuthAttrs);
                        var subjectId = new UniversalSubjectIdentifier(signerInfo.Issuer, signerInfo.SerialNumber);
                        if (subjectId.Type == SubjectIdentifierType.SubjectKeyIdentifier)
                        {
                            Certificate = FindCertificate((string)subjectId.Value, OwningSignature.AdditionalCertificates);
                        }
                        else if (subjectId.Type == SubjectIdentifierType.IssuerAndSerialNumber)
                        {
                            Certificate = FindCertificate((X509IssuerSerial)subjectId.Value, OwningSignature.AdditionalCertificates);
                        }
                    }
                }
                else
                {
                    throw new InvalidOperationException("Failed to read Authenticode signature");
                }
            }
        }

        /// <inheritdoc />
        public override IReadOnlyList<ICmsSignature> GetNestedSignatures()
        {
            var list = new List<ICmsSignature>();
            foreach (var attribute in UnsignedAttributes)
            {
                foreach (var value in attribute.Values)
                {
                    ICmsSignature signature;
                    switch (attribute.Oid.Value)
                    {
                        case KnownOids.AuthenticodeCounterSignature:
                            signature = new AuthenticodeTimestampCmsSignature(value, OwningSignature);
                            break;
                        case KnownOids.Rfc3161CounterSignature:
                            signature = new CmsSignature(value, SignatureKind.Rfc3161Timestamp);
                            break;
                        case KnownOids.NestedSignatureOid:
                            signature = new CmsSignature(value, SignatureKind.NestedSignature);
                            break;
                        default:
                            continue;
                    }
                    list.Add(signature);
                }
            }
            return list.AsReadOnly();
        }
    }

    /// <summary>
    /// A class that represents an Authenticode signature.
    /// </summary>
    public sealed class CmsSignature : CmsSignatureBase
    {
        internal CmsSignature(SignatureKind kind, CryptMsgSafeHandle messageHandle, LocalBufferSafeHandle signerHandle, byte[]? content)
        {
            Content = content;
            Kind = kind;
            InitFromHandles(messageHandle, signerHandle);
        }

        internal unsafe CmsSignature(AsnEncodedData data, SignatureKind kind)
        {
            Kind = kind;
            fixed (byte* pin = data.RawData)
            {
                var blob = new CRYPTOAPI_BLOB
                {
                    cbData = (uint)data.RawData.Length,
                    pbData = new IntPtr(pin)
                };
                var result = Crypt32.CryptQueryObject(
                    CryptQueryObjectType.CERT_QUERY_OBJECT_BLOB,
                    ref blob,
                    CryptQueryContentFlagType.CERT_QUERY_CONTENT_FLAG_ALL,
                    CryptQueryFormatFlagType.CERT_QUERY_FORMAT_FLAG_BINARY,
                    CryptQueryObjectFlags.NONE,
                    out var encodingType,
                    out var contentType,
                    out var formatType,
                    IntPtr.Zero,
                    out var msgHandle,
                    IntPtr.Zero);
                if (!result)
                {
                    msgHandle.Dispose();
                    throw new InvalidOperationException("Unable to read signature.");
                }
                var contentSize = 0u;
                if (Crypt32.CryptMsgGetParam(msgHandle, CryptMsgParamType.CMSG_CONTENT_PARAM, 0, LocalBufferSafeHandle.Zero, ref contentSize))
                {
                    using var contentHandle = LocalBufferSafeHandle.Alloc(contentSize);
                    if (Crypt32.CryptMsgGetParam(msgHandle, CryptMsgParamType.CMSG_CONTENT_PARAM, 0, contentHandle, ref contentSize))
                    {
                        Content = new byte[contentSize];
                        Marshal.Copy(contentHandle.DangerousGetHandle(), Content, 0, (int)contentSize);
                    }
                }
                var signerSize = 0u;
                if (!Crypt32.CryptMsgGetParam(msgHandle, CryptMsgParamType.CMSG_SIGNER_INFO_PARAM, 0, LocalBufferSafeHandle.Zero, ref signerSize))
                {
                    throw new InvalidOperationException();
                }
                using var signerHandle = LocalBufferSafeHandle.Alloc(signerSize);
                if (!Crypt32.CryptMsgGetParam(msgHandle, CryptMsgParamType.CMSG_SIGNER_INFO_PARAM, 0, signerHandle, ref signerSize))
                {
                    throw new InvalidOperationException();
                }
                InitFromHandles(msgHandle, signerHandle);
            }
        }

        private void InitFromHandles(CryptMsgSafeHandle messageHandle, LocalBufferSafeHandle signerHandle)
        {
            var signerInfo = Marshal.PtrToStructure<CMSG_SIGNER_INFO>(signerHandle.DangerousGetHandle());
            Signature = ReadBlob(signerInfo.EncryptedHash);
            var subjectId = new UniversalSubjectIdentifier(signerInfo.Issuer, signerInfo.SerialNumber);
            var certs = GetCertificatesFromMessage(messageHandle);
            if (subjectId.Type == SubjectIdentifierType.SubjectKeyIdentifier)
            {
                Certificate = FindCertificate((string)subjectId.Value, certs);
            }
            else if (subjectId.Type == SubjectIdentifierType.IssuerAndSerialNumber)
            {
                Certificate = FindCertificate((X509IssuerSerial)subjectId.Value, certs);
            }
            AdditionalCertificates = certs;
            DigestAlgorithm = new Oid(signerInfo.HashAlgorithm.pszObjId);
            HashEncryptionAlgorithm = new Oid(signerInfo.HashEncryptionAlgorithm.pszObjId);
            SerialNumber = ReadBlob(signerInfo.SerialNumber);
            UnsignedAttributes = ReadAttributes(signerInfo.UnauthAttrs);
            SignedAttributes = ReadAttributes(signerInfo.AuthAttrs);
        }

        /// <inheritdoc />
        public override IReadOnlyList<ICmsSignature> GetNestedSignatures()
        {
            var list = new List<ICmsSignature>();
            foreach (var attribute in UnsignedAttributes)
            {
                foreach (var value in attribute.Values)
                {
                    ICmsSignature signature;
                    switch (attribute.Oid.Value)
                    {
                        case KnownOids.AuthenticodeCounterSignature:
                            signature = new AuthenticodeTimestampCmsSignature(value, this);
                            break;
                        case KnownOids.Rfc3161CounterSignature:
                            signature = new CmsSignature(value, SignatureKind.Rfc3161Timestamp);
                            break;
                        case KnownOids.NestedSignatureOid:
                            signature = new CmsSignature(value, SignatureKind.NestedSignature);
                            break;
                        default:
                            continue;
                    }
                    list.Add(signature);
                }
            }
            return list.AsReadOnly();
        }
    }

    internal class UniversalSubjectIdentifier
    {
        public SubjectIdentifierType Type { get; }
        public object Value { get; }

        public UniversalSubjectIdentifier(CRYPTOAPI_BLOB issuer, CRYPTOAPI_BLOB serialNumber)
        {
            var allZeroSerial = IsBlobAllZero(serialNumber);
            if (allZeroSerial)
            {
                var x500Name = LocalBufferSafeHandle.Zero;
                var flags = EncodingType.PKCS_7_ASN_ENCODING | EncodingType.X509_ASN_ENCODING;
                uint size = 0;
                if (Crypt32.CryptDecodeObjectEx(flags, (IntPtr)7, issuer.pbData, issuer.cbData, CryptDecodeFlags.CRYPT_DECODE_ALLOC_FLAG, IntPtr.Zero, out x500Name, ref size))
                {
                    using (x500Name)
                    {
                        var info = Marshal.PtrToStructure<CERT_NAME_INFO>(x500Name.DangerousGetHandle());
                        for (var i = 0L; i < info.cRDN; i++)
                        {
                            var rdn = Marshal.PtrToStructure<CERT_RDN>(new IntPtr(info.rgRDN.ToInt64() + i * Marshal.SizeOf<CERT_RDN>()));
                            for (var j = 0; j < rdn.cRDNAttr; j++)
                            {
                                var attribute = Marshal.PtrToStructure<CERT_RDN_ATTR>(new IntPtr(rdn.rgRDNAttr.ToInt64() + j * Marshal.SizeOf<CERT_RDN_ATTR>()));
                                if (attribute.pszObjId == KnownOids.KeyId)
                                {
                                    Type = SubjectIdentifierType.SubjectKeyIdentifier;
                                    var ski = attribute.Value.AsSpan();
                                    Value = HexHelpers.HexEncodeBigEndian(ski);
                                    return;
                                }
                            }
                        }
                    }
                }
            }
            unsafe
            {
                var result = Crypt32.CertNameToStr(EncodingType.PKCS_7_ASN_ENCODING | EncodingType.X509_ASN_ENCODING, new IntPtr(&issuer), CertNameStrType.CERT_X500_NAME_STR | CertNameStrType.CERT_NAME_STR_REVERSE_FLAG, null, 0);
                if (result <= 1)
                {
                    throw new InvalidOperationException();
                }
                var builder = new StringBuilder((int)result);
                var final = Crypt32.CertNameToStr(EncodingType.PKCS_7_ASN_ENCODING | EncodingType.X509_ASN_ENCODING, new IntPtr(&issuer), CertNameStrType.CERT_X500_NAME_STR | CertNameStrType.CERT_NAME_STR_REVERSE_FLAG, builder, result);
                if (final <= 1)
                {
                    throw new InvalidOperationException();
                }
                var serial = serialNumber.AsSpan();
                var issuerSerial = new X509IssuerSerial
                {
                    IssuerName = builder.ToString(),
                    SerialNumber = HexHelpers.HexEncodeBigEndian(serial)
                };
                Value = issuerSerial;
                Type = SubjectIdentifierType.IssuerAndSerialNumber;
            }
        }

        private static bool IsBlobAllZero(CRYPTOAPI_BLOB blob)
        {
            var data = blob.AsSpan();
            for (var i = 0; i < data.Length; i++)
            {
                if (data[i] != 0)
                {
                    return false;
                }
            }
            return true;

        }
    }
}
