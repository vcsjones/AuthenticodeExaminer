using AuthenticodeExaminer.Interop;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace AuthenticodeExaminer
{
    /// <summary>
    /// Provides low-level access to the Authenticode signatures in a file that allows
    /// Inspecting the order and nesting of the signatures.
    /// </summary>
    public static class SignatureTreeInspector
    {
        /// <summary>
        /// Extracts the immediate root signatures from a file, or an empty collection if not signed.
        /// </summary>
        /// <param name="filePath">The path to the file to extract signatures from.</param>
        /// <returns>A collection of signatures in the file.</returns>
        public static IReadOnlyList<ICmsSignature> Extract(string filePath)
        {
            CryptMsgSafeHandle message = CryptMsgSafeHandle.InvalidHandle;
            var result = Crypt32.CryptQueryObject(
                CryptQueryObjectType.CERT_QUERY_OBJECT_FILE,
                filePath,
                CryptQueryContentFlagType.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CryptQueryFormatFlagType.CERT_QUERY_FORMAT_FLAG_BINARY,
                CryptQueryObjectFlags.NONE,
                out var encodingType, out var contentType, out var formatType,
                IntPtr.Zero, out message, IntPtr.Zero);
            if (!result)
            {
                var resultCode = Marshal.GetLastWin32Error();
                switch (unchecked((uint)resultCode))
                {
                    case 0x80092009: //Cannot find request object. There's no signature.
                        return Array.Empty<ICmsSignature>();
                    default:
                        throw new Win32Exception(resultCode, "Failed to extract signature.");
                }
            }
            using (message)
            {
                if (message.IsInvalid || message.IsClosed)
                {
                    return Array.Empty<ICmsSignature>();
                }
                return GetSignatures(message);
            }
        }

        private static unsafe IReadOnlyList<ICmsSignature> GetSignatures(CryptMsgSafeHandle messageHandle)
        {
            var countSize = 0u;
            if (!Crypt32.CryptMsgGetParam(messageHandle, CryptMsgParamType.CMSG_SIGNER_COUNT_PARAM, 0, LocalBufferSafeHandle.Zero, ref countSize))
            {
                return Array.Empty<ICmsSignature>();
            }
            uint signerCount;
            using (var countHandle = LocalBufferSafeHandle.Alloc(countSize))
            {
                if (!Crypt32.CryptMsgGetParam(messageHandle, CryptMsgParamType.CMSG_SIGNER_COUNT_PARAM, 0, countHandle, ref countSize))
                {
                    return Array.Empty<ICmsSignature>();
                }
                signerCount = (uint)Marshal.ReadInt32(countHandle.DangerousGetHandle());
            }
            var signatures = new List<ICmsSignature>();
            var contentSize = 0u;
            byte[] content = null;
            if (Crypt32.CryptMsgGetParam(messageHandle, CryptMsgParamType.CMSG_CONTENT_PARAM, 0, LocalBufferSafeHandle.Zero, ref contentSize))
            {
                using (var contentHandle = LocalBufferSafeHandle.Alloc(contentSize))
                {
                    if (Crypt32.CryptMsgGetParam(messageHandle, CryptMsgParamType.CMSG_CONTENT_PARAM, 0, contentHandle, ref contentSize))
                    {
                        content = new byte[contentSize];
                        Marshal.Copy(contentHandle.DangerousGetHandle(), content, 0, (int)contentSize);
                    }
                }
            }
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
                    var signature = new CmsSignature(SignatureKind.Signature, messageHandle, signerHandle, content);
                    signatures.Add(signature);
                }
            }
            return signatures.AsReadOnly();
        }
    }
}
