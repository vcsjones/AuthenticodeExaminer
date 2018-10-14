using AuthenticodeExaminer.Interop;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Text;

namespace AuthenticodeExaminer
{
    public class SigningTime
    {
        public DateTimeOffset Time { get; }

        public SigningTime(AsnEncodedData data)
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
                    long fileTimeVal = ((long)time.dwHighDateTime) << 32 | (long)time.dwLowDateTime;
                    Time = DateTimeOffset.FromFileTime(fileTimeVal);
                }
            }
        }
    }
}
