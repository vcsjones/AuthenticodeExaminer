using AuthenticodeExaminer.Interop;
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;

namespace AuthenticodeExaminer
{
    internal class TimestampDecoding
    {
        public static DateTimeOffset? DecodeAuthenticodeTimestamp(AsnEncodedData data)
        {
            if (data.Oid.Value != KnownOids.SigningTime)
            {
                throw new ArgumentException("Data is not a signing time object.", nameof(data));
            }
            const EncodingType encodingType = EncodingType.PKCS_7_ASN_ENCODING | EncodingType.X509_ASN_ENCODING;
            unsafe
            {
                LocalBufferSafeHandle structBuffer;
                fixed (byte* buffer = data.RawData)
                {
                    uint size = 0;
                    if (!Crypt32.CryptDecodeObjectEx(encodingType, KnownOids.SigningTime, buffer, (uint)data.RawData.Length, CryptDecodeFlags.CRYPT_DECODE_ALLOC_FLAG, IntPtr.Zero, out structBuffer, ref size))
                    {
                        throw new InvalidOperationException("Failed to decode data.");
                    }
                }
                using (structBuffer)
                {
                    var time = Marshal.PtrToStructure<FILETIME>(structBuffer.DangerousGetHandle());
                    long fileTimeVal = ((long)time.dwHighDateTime) << 32 | (uint)time.dwLowDateTime;
                    return DateTimeOffset.FromFileTime(fileTimeVal);
                }
            }
        }

        public static unsafe DateTimeOffset? DecodeRfc3161(byte[] content)
        {
            fixed (byte* contentPtr = content)
            {
                var sequenceSize = 0u;
                LocalBufferSafeHandle sequenceBuffer;
                if (!Crypt32.CryptDecodeObjectEx(EncodingType.PKCS_7_ASN_ENCODING | EncodingType.X509_ASN_ENCODING, (IntPtr)34, new IntPtr(contentPtr), (uint)content.Length, CryptDecodeFlags.CRYPT_DECODE_ALLOC_FLAG, IntPtr.Zero, out sequenceBuffer, ref sequenceSize))
                {
                    return null;
                }

                using (sequenceBuffer)
                {
                    var sequenceStruct = Marshal.PtrToStructure<CRYPT_SEQUENCE_OF_ANY>(sequenceBuffer.DangerousGetHandle());
                    if (sequenceStruct.cValue < 5)
                    {
                        return null;
                    }
                    var time = sequenceStruct.rgValue[4];
                    var timeSize = 0u;
                    LocalBufferSafeHandle timeBuffer;
                    if (!Crypt32.CryptDecodeObjectEx(EncodingType.PKCS_7_ASN_ENCODING | EncodingType.X509_ASN_ENCODING, (IntPtr)30, time.pbData, time.cbData, CryptDecodeFlags.CRYPT_DECODE_ALLOC_FLAG, IntPtr.Zero, out timeBuffer, ref timeSize))
                    {
                        return null;
                    }

                    using (timeBuffer)
                    {
                        var fileTime = Marshal.PtrToStructure<FILETIME>(timeBuffer.DangerousGetHandle());
                        long fileTimeVal = ((long)fileTime.dwHighDateTime) << 32 | (uint)fileTime.dwLowDateTime;
                        return DateTimeOffset.FromFileTime(fileTimeVal);
                    }
                }
            }
        }
    }
}
