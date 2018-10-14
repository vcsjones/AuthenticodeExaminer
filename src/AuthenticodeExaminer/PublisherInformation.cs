using AuthenticodeExaminer.Interop;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AuthenticodeExaminer
{
    public class PublisherInformation
    {
        public string Description { get; }
        public string UrlLink { get; }
        public string FileLink { get; }

        public PublisherInformation(AsnEncodedData data)
        {
            if (data.Oid.Value != KnownOids.OpusInfo)
            {
                throw new ArgumentException("Data is not a publisher information object.", nameof(data));
            }
            const EncodingType encodingType = EncodingType.PKCS_7_ASN_ENCODING | EncodingType.X509_ASN_ENCODING;
            unsafe
            {
                LocalBufferSafeHandle structBuffer;
                fixed (byte* buffer = data.RawData)
                {
                    uint size = 0;
                    if (!Crypt32.CryptDecodeObjectEx(encodingType, KnownOids.OpusInfo, buffer, (uint)data.RawData.Length, CryptDecodeFlags.CRYPT_DECODE_ALLOC_FLAG, IntPtr.Zero, out structBuffer, ref size))
                    {
                        throw new InvalidOperationException("Failed to decode data.");
                    }
                }
                using (structBuffer)
                {
                    var info = Marshal.PtrToStructure<SPC_SP_OPUS_INFO>(structBuffer.DangerousGetHandle());
                    Description = info.pwszProgramName;
                    if (info.pMoreInfo != null)
                    {
                        var moreInfo = info.pMoreInfo;
                        switch (moreInfo->dwLinkChoice)
                        {
                            case SpcLinkChoice.SPC_URL_LINK_CHOICE:
                                UrlLink = Marshal.PtrToStringUni(moreInfo->linkUnion.pwszUrl);
                                break;
                            case SpcLinkChoice.SPC_FILE_LINK_CHOICE:
                                FileLink = Marshal.PtrToStringUni(moreInfo->linkUnion.pwszFile);
                                break;
                        }
                    }
                }
            }
        }
    }
}
