using System;
using System.Runtime.InteropServices;
using System.Text;

namespace AuthenticodeExaminer.Interop
{
    internal static class Crypt32
    {
        [method: DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, EntryPoint = "CryptQueryObject", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptQueryObject
        (
            [param: In, MarshalAs(UnmanagedType.U4)] CryptQueryObjectType dwObjectType,
            [param: In, MarshalAs(UnmanagedType.LPWStr)] string pvObject,
            [param: In, MarshalAs(UnmanagedType.U4)] CryptQueryContentFlagType dwExpectedContentTypeFlags,
            [param: In, MarshalAs(UnmanagedType.U4)] CryptQueryFormatFlagType dwExpectedFormatTypeFlags,
            [param: In, MarshalAs(UnmanagedType.U4)] CryptQueryObjectFlags dwFlags,
            [param: Out, MarshalAs(UnmanagedType.U4)] out EncodingType pdwMsgAndCertEncodingType,
            [param: Out, MarshalAs(UnmanagedType.U4)] out CryptQueryContentType pdwContentType,
            [param: Out, MarshalAs(UnmanagedType.U4)] out CryptQueryFormatType pdwFormatType,
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr phCertStore,
            [param: Out] out CryptMsgSafeHandle phMsg,
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr ppvContext
         );

        [method: DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, EntryPoint = "CryptQueryObject", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptQueryObject
        (
            [param: In, MarshalAs(UnmanagedType.U4)] CryptQueryObjectType dwObjectType,
            [param: In, Out, MarshalAs(UnmanagedType.Struct)] ref CRYPTOAPI_BLOB pvObject,
            [param: In, MarshalAs(UnmanagedType.U4)] CryptQueryContentFlagType dwExpectedContentTypeFlags,
            [param: In, MarshalAs(UnmanagedType.U4)] CryptQueryFormatFlagType dwExpectedFormatTypeFlags,
            [param: In, MarshalAs(UnmanagedType.U4)] CryptQueryObjectFlags dwFlags,
            [param: Out, MarshalAs(UnmanagedType.U4)] out EncodingType pdwMsgAndCertEncodingType,
            [param: Out, MarshalAs(UnmanagedType.U4)] out CryptQueryContentType pdwContentType,
            [param: Out, MarshalAs(UnmanagedType.U4)] out CryptQueryFormatType pdwFormatType,
            [param: In, MarshalAs(UnmanagedType.SysInt)]  IntPtr phCertStore,
            [param: Out] out CryptMsgSafeHandle phMsg,
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr ppvContext
         );

        [method: DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, EntryPoint = "CryptDecodeObjectEx", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern unsafe bool CryptDecodeObjectEx
        (
            [param: In, MarshalAs(UnmanagedType.U4)] EncodingType dwCertEncodingType,
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr lpszStructType,
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr pbEncoded,
            [param: In, MarshalAs(UnmanagedType.U4)] uint cbEncoded,
            [param: In, MarshalAs(UnmanagedType.U4)] CryptDecodeFlags dwFlags,
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr pDecodePara,
            [param: Out] out LocalBufferSafeHandle pvStructInfo,
            [param: In, Out, MarshalAs(UnmanagedType.U4)] ref uint pcbStructInfo
        );

        [method: DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, EntryPoint = "CryptDecodeObjectEx", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern unsafe bool CryptDecodeObjectEx
        (
            [param: In, MarshalAs(UnmanagedType.U4)] EncodingType dwCertEncodingType,
            [param: In, MarshalAs(UnmanagedType.LPStr)] string lpszStructType,
            [param: In] void* pbEncoded,
            [param: In, MarshalAs(UnmanagedType.U4)] uint cbEncoded,
            [param: In, MarshalAs(UnmanagedType.U4)] CryptDecodeFlags dwFlags,
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr pDecodePara,
            [param: Out] out LocalBufferSafeHandle pvStructInfo,
            [param: In, Out, MarshalAs(UnmanagedType.U4)] ref uint pcbStructInfo
        );

        [method: DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, EntryPoint = "CryptMsgClose", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptMsgClose([param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr hCryptMsg);

        [method: DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, EntryPoint = "CertCloseStore", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CertCloseStore
        (
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr hCertStore,
            [param: In, MarshalAs(UnmanagedType.U4)] uint dwFlags
        );

        [method: DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, EntryPoint = "CryptMsgGetParam", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static unsafe extern bool CryptMsgGetParam
        (
            [param: In] CryptMsgSafeHandle hCryptMsg,
            [param: In, MarshalAs(UnmanagedType.U4)] CryptMsgParamType dwParamType,
            [param: In, MarshalAs(UnmanagedType.U4)] uint dwIndex,
            [param: In] LocalBufferSafeHandle pvData,
            [param: In, Out, MarshalAs(UnmanagedType.U4)] ref uint pcbData
        );

        [method: DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, EntryPoint = "CryptBinaryToString", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static unsafe extern bool CryptBinaryToString
        (
            [param: In] byte[] pbBinary,
            [param: In, MarshalAs(UnmanagedType.U4)] uint cbBinary,
            [param: In, MarshalAs(UnmanagedType.U4)] CryptBinaryToStringFlags dwFlags,
            [param: In, Out] StringBuilder pszString,
            [param: In, Out] ref uint pcchString
        );

        [method: DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, EntryPoint = "CertNameToStr", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static unsafe extern uint CertNameToStr
        (
            [param: In, MarshalAs(UnmanagedType.U4)] EncodingType dwCertEncodingType,
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr pName,
            [param: In, MarshalAs(UnmanagedType.U4)] CertNameStrType dwStrType,
            [param: In, Out] StringBuilder? psz,
            [param: In] uint csz
        );
    }

    [type: Flags]
    internal enum CertNameStrType : uint
    {
        CERT_SIMPLE_NAME_STR = 1,
        CERT_OID_NAME_STR = 2,
        CERT_X500_NAME_STR = 3,

        CERT_NAME_STR_SEMICOLON_FLAG = 0x40000000,
        CERT_NAME_STR_CRLF_FLAG = 0x08000000,
        CERT_NAME_STR_NO_PLUS_FLAG = 0x20000000,
        CERT_NAME_STR_NO_QUOTING_FLAG = 0x10000000,
        CERT_NAME_STR_REVERSE_FLAG = 0x02000000,
        CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG = 0x00010000,
        CERT_NAME_STR_ENABLE_PUNYCODE_FLAG = 0x00200000
    }

    internal enum CryptBinaryToStringFlags : uint
    {
        CRYPT_STRING_BASE64HEADER = 0x00000000,
        CRYPT_STRING_BASE64 = 0x00000001,
        CRYPT_STRING_BINARY = 0x00000002,
        CRYPT_STRING_BASE64REQUESTHEADER = 0x00000003,
        CRYPT_STRING_HEX = 0x00000004,
        CRYPT_STRING_HEXASCII = 0x00000005,
        CRYPT_STRING_BASE64X509CRLHEADER = 0x00000009,
        CRYPT_STRING_HEXADDR = 0x0000000a,
        CRYPT_STRING_HEXASCIIADDR = 0x0000000b,
        CRYPT_STRING_HEXRAW = 0x0000000c,
        CRYPT_STRING_STRICT = 0x20000000,

        CRYPT_STRING_NOCRLF = 0x40000000,
        CRYPT_STRING_NOCR = 0x80000000,

    }

    internal enum CryptQueryObjectType : uint
    {
        CERT_QUERY_OBJECT_FILE = 0x00000001,
        CERT_QUERY_OBJECT_BLOB = 0x00000002
    }

    internal enum CryptMsgParamType : uint
    {
        CMSG_TYPE_PARAM = 1,
        CMSG_CONTENT_PARAM = 2,
        CMSG_BARE_CONTENT_PARAM = 3,
        CMSG_INNER_CONTENT_TYPE_PARAM = 4,
        CMSG_SIGNER_COUNT_PARAM = 5,
        CMSG_SIGNER_INFO_PARAM = 6,
        CMSG_SIGNER_CERT_INFO_PARAM = 7,
        CMSG_SIGNER_HASH_ALGORITHM_PARAM = 8,
        CMSG_SIGNER_AUTH_ATTR_PARAM = 9,
        CMSG_SIGNER_UNAUTH_ATTR_PARAM = 10,
        CMSG_CERT_COUNT_PARAM = 11,
        CMSG_CERT_PARAM = 12,
        CMSG_CRL_COUNT_PARAM = 13,
        CMSG_CRL_PARAM = 14,
        CMSG_ENVELOPE_ALGORITHM_PARAM = 15,
        CMSG_RECIPIENT_COUNT_PARAM = 17,
        CMSG_RECIPIENT_INDEX_PARAM = 18,
        CMSG_RECIPIENT_INFO_PARAM = 19,
        CMSG_HASH_ALGORITHM_PARAM = 20,
        CMSG_HASH_DATA_PARAM = 21,
        CMSG_COMPUTED_HASH_PARAM = 22,
        CMSG_ENCRYPT_PARAM = 26,
        CMSG_ENCRYPTED_DIGEST = 27,
        CMSG_ENCODED_SIGNER = 28,
        CMSG_ENCODED_MESSAGE = 29,
        CMSG_VERSION_PARAM = 30,
        CMSG_ATTR_CERT_COUNT_PARAM = 31,
        CMSG_ATTR_CERT_PARAM = 32,
        CMSG_CMS_RECIPIENT_COUNT_PARAM = 33,
        CMSG_CMS_RECIPIENT_INDEX_PARAM = 34,
        CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM = 35,
        CMSG_CMS_RECIPIENT_INFO_PARAM = 36,
        CMSG_UNPROTECTED_ATTR_PARAM = 37,
        CMSG_SIGNER_CERT_ID_PARAM = 38,
        CMSG_CMS_SIGNER_INFO_PARAM = 39,
    }

    [type: Flags]
    internal enum CryptQueryContentFlagType : uint
    {
        CERT_QUERY_CONTENT_FLAG_CERT = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_CERT,
        CERT_QUERY_CONTENT_FLAG_CTL = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_CTL,
        CERT_QUERY_CONTENT_FLAG_CRL = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_CRL,
        CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_SERIALIZED_STORE,
        CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_SERIALIZED_CERT,
        CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_SERIALIZED_CTL,
        CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_SERIALIZED_CRL,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_PKCS7_SIGNED,
        CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_PKCS7_UNSIGNED,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED,
        CERT_QUERY_CONTENT_FLAG_PKCS10 = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_PKCS10,
        CERT_QUERY_CONTENT_FLAG_PFX = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_PFX,
        CERT_QUERY_CONTENT_FLAG_CERT_PAIR = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_CERT_PAIR,
        CERT_QUERY_CONTENT_FLAG_PFX_AND_LOAD = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_PFX_AND_LOAD,
        CERT_QUERY_CONTENT_FLAG_ALL =
            CERT_QUERY_CONTENT_FLAG_CERT |
            CERT_QUERY_CONTENT_FLAG_CTL |
            CERT_QUERY_CONTENT_FLAG_CRL |
            CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE |
            CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT |
            CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL |
            CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL |
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
            CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED |
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED |
            CERT_QUERY_CONTENT_FLAG_PKCS10 |
            CERT_QUERY_CONTENT_FLAG_PFX |
            CERT_QUERY_CONTENT_FLAG_CERT_PAIR, //wincrypt.h purposefully omits CERT_QUERY_CONTENT_FLAG_PFX_AND_LOAD
        CERT_QUERY_CONTENT_FLAG_ALL_ISSUER_CERT =
            CERT_QUERY_CONTENT_FLAG_CERT |
            CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE |
            CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT |
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
            CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED
    }

    internal enum CryptQueryContentType : uint
    {
        CERT_QUERY_CONTENT_CERT = 1,
        CERT_QUERY_CONTENT_CTL = 2,
        CERT_QUERY_CONTENT_CRL = 3,
        CERT_QUERY_CONTENT_SERIALIZED_STORE = 4,
        CERT_QUERY_CONTENT_SERIALIZED_CERT = 5,
        CERT_QUERY_CONTENT_SERIALIZED_CTL = 6,
        CERT_QUERY_CONTENT_SERIALIZED_CRL = 7,
        CERT_QUERY_CONTENT_PKCS7_SIGNED = 8,
        CERT_QUERY_CONTENT_PKCS7_UNSIGNED = 9,
        CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED = 10,
        CERT_QUERY_CONTENT_PKCS10 = 11,
        CERT_QUERY_CONTENT_PFX = 12,
        CERT_QUERY_CONTENT_CERT_PAIR = 13,
        CERT_QUERY_CONTENT_PFX_AND_LOAD = 14
    }

    internal enum CryptQueryFormatType : uint
    {
        CERT_QUERY_FORMAT_BINARY = 1,
        CERT_QUERY_FORMAT_BASE64_ENCODED = 2,
        CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED = 3
    }

    [type: Flags]
    internal enum CryptQueryFormatFlagType : uint
    {
        CERT_QUERY_FORMAT_FLAG_BINARY = 1u << (int)CryptQueryFormatType.CERT_QUERY_FORMAT_BINARY,
        CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED = 1u << (int)CryptQueryFormatType.CERT_QUERY_FORMAT_BASE64_ENCODED,
        CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED = 1u << (int)CryptQueryFormatType.CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED,
        CERT_QUERY_FORMAT_FLAG_ALL =
            CERT_QUERY_FORMAT_FLAG_BINARY |
            CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED |
            CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED
    }

    [type: Flags]
    internal enum CryptQueryObjectFlags : uint
    {
        NONE = 0
    }

    internal enum EncodingType : uint
    {
        PKCS_7_ASN_ENCODING = 0x10000,
        X509_ASN_ENCODING = 0x1
    }

    [type: Flags]
    internal enum CryptDecodeFlags : uint
    {
        CRYPT_DECODE_ALLOC_FLAG = 0x8000
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct CRYPTOAPI_BLOB
    {
        public uint cbData;
        public IntPtr pbData;

        public unsafe ReadOnlySpan<byte> AsSpan()
        {
            return new ReadOnlySpan<byte>(pbData.ToPointer(), checked((int)cbData));
        }
    }

    [type: StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal struct CRYPT_ALGORITHM_IDENTIFIER
    {
        public string pszObjId;
        public CRYPTOAPI_BLOB Parameters;
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct CMSG_SIGNER_INFO
    {
        public uint dwVersion;
        public CRYPTOAPI_BLOB Issuer;
        public CRYPTOAPI_BLOB SerialNumber;
        public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
        public CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;
        public CRYPTOAPI_BLOB EncryptedHash;
        public CRYPT_ATTRIBUTES AuthAttrs;
        public CRYPT_ATTRIBUTES UnauthAttrs;
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_ATTRIBUTES
    {
        public uint cAttr;
        public IntPtr rgAttr;
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct SPC_SP_OPUS_INFO
    {
        [field: MarshalAs(UnmanagedType.LPWStr)]
        public string pwszProgramName;

        public unsafe SPC_LINK* pMoreInfo;
        public unsafe SPC_LINK* pPublisherInfo;
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct SPC_LINK
    {
        public SpcLinkChoice dwLinkChoice;
        public SPC_LINK_UNION linkUnion;
    }

    [type: StructLayout(LayoutKind.Explicit)]
    internal struct SPC_LINK_UNION
    {
        [field: FieldOffset(0)]
        public IntPtr pwszUrl;

        [field: FieldOffset(0)]
        public SPC_SERIALIZED_OBJECT Moniker;

        [field: FieldOffset(0)]
        public IntPtr pwszFile;
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct SPC_SERIALIZED_OBJECT
    {
        public unsafe fixed byte ClassId[16];
        public CRYPTOAPI_BLOB SerializedData;
    }

    internal enum SpcLinkChoice : uint
    {
        SPC_URL_LINK_CHOICE = 1,
        SPC_MONIKER_LINK_CHOICE = 2,
        SPC_FILE_LINK_CHOICE = 3
    }

    [type: StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal struct CRYPT_ATTRIBUTE
    {
        public string pszObjId;
        public uint cValue;
        public IntPtr rgValue;
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct CERT_NAME_INFO
    {
        public uint cRDN;
        public IntPtr rgRDN;
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct CERT_RDN
    {
        public uint cRDNAttr;
        public IntPtr rgRDNAttr;
    }

    [type: StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal struct CERT_RDN_ATTR
    {
        public string pszObjId;
        public uint dwValueType;
        public CRYPTOAPI_BLOB Value;
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_SEQUENCE_OF_ANY
    {
        public uint cValue;
        public unsafe CRYPTOAPI_BLOB* rgValue;
    }
}
