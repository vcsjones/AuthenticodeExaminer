using AuthenticodeExaminer.Interop;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace AuthenticodeExaminer
{
    public class SignatureExtractor
    {
        public IReadOnlyList<ISignature> Extract(string filePath)
        {
            EncodingType encodingType;
            CryptQueryContentType contentType;
            CryptQueryFormatType formatType;
            CryptMsgSafeHandle message = CryptMsgSafeHandle.InvalidHandle;
            var result = Crypt32.CryptQueryObject(CryptQueryObjectType.CERT_QUERY_OBJECT_FILE, filePath, CryptQueryContentFlagType.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CryptQueryFormatFlagType.CERT_QUERY_FORMAT_FLAG_BINARY, CryptQueryObjectFlags.NONE, out encodingType, out contentType, out formatType, IntPtr.Zero, out message, IntPtr.Zero);
            if (!result)
            {
                var resultCode = Marshal.GetLastWin32Error();
                switch (unchecked((uint)resultCode))
                {
                    case 0x80092009: //Cannot find request object. There's no signature.
                        return Array.Empty<ISignature>();
                    default:
                        throw new Win32Exception(resultCode, "Failed to extract signature.");
                }
            }
            using (message)
            {
                if (message.IsInvalid || message.IsClosed)
                {
                    return Array.Empty<ISignature>();
                }
                return GetSignatures(message);
            }
        }

        private unsafe IReadOnlyList<ISignature> GetSignatures(CryptMsgSafeHandle messageHandle)
        {
            var countSize = 0u;
            if (!Crypt32.CryptMsgGetParam(messageHandle, CryptMsgParamType.CMSG_SIGNER_COUNT_PARAM, 0, LocalBufferSafeHandle.Zero, ref countSize))
            {
                return Array.Empty<ISignature>();
            }
            uint signerCount;
            using (var countHandle = LocalBufferSafeHandle.Alloc(countSize))
            {
                if (!Crypt32.CryptMsgGetParam(messageHandle, CryptMsgParamType.CMSG_SIGNER_COUNT_PARAM, 0, countHandle, ref countSize))
                {
                    return Array.Empty<ISignature>();
                }
                signerCount = (uint)Marshal.ReadInt32(countHandle.DangerousGetHandle());
            }
            var signatures = new List<ISignature>();
            for (var i = 0u; i < signerCount; i++)
            {
                var signerSize = 0u;
                if (!Crypt32.CryptMsgGetParam(messageHandle, CryptMsgParamType.CMSG_SIGNER_INFO_PARAM, i, LocalBufferSafeHandle.Zero, ref signerSize))
                {
                    continue;
                }
                using (var signerHandle = LocalBufferSafeHandle.Alloc(signerSize))
                {
                    if (!Crypt32.CryptMsgGetParam(messageHandle, CryptMsgParamType.CMSG_SIGNER_INFO_PARAM, i, signerHandle, ref signerSize))
                    {
                        continue;
                    }
                    var signature = new Signature(SignatureKind.Signature, messageHandle, signerHandle);
                    signatures.Add(signature);
                }
            }
            return signatures.AsReadOnly();
        }
    }
}
