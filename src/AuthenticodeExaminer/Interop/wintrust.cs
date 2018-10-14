using System;
using System.Runtime.InteropServices;

namespace AuthenticodeExaminer.Interop
{
    internal static class Wintrust
    {
        [method: DllImport("wintrust.dll", EntryPoint = "WinVerifyTrustEx", CallingConvention = CallingConvention.Winapi, SetLastError = false)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern unsafe int WinVerifyTrustEx
            (
                [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr hwnd,
                [param: In, MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
                [param: In] WINTRUST_DATA* pWVTData
            );
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public WinTrustDataUIChoice dwUIChoice;
        public WinTrustRevocationChecks fdwRevocationChecks;
        public WinTrustUnionChoice dwUnionChoice;
        public WINTRUST_DATA_UNION trustUnion;
        public WinTrustStateAction dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public WinTrustProviderFlags dwProvFlags;
        public WinTrustUIContext dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [type: StructLayout(LayoutKind.Explicit)]
    internal unsafe struct WINTRUST_DATA_UNION
    {
        [field: FieldOffset(0)]
        public WINTRUST_FILE_INFO* pFile;
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }


    internal enum WinTrustDataUIChoice : uint
    {
        WTD_UI_ALL = 1,
        WTD_UI_NONE = 2,
        WTD_UI_NOBAD = 3,
        WTD_UI_NOGOOD = 4,
    }

    internal enum WinTrustRevocationChecks : uint
    {
        WTD_REVOKE_NONE = 0,
        WTD_REVOKE_WHOLECHAIN = 1
    }

    internal enum WinTrustUnionChoice : uint
    {
        WTD_CHOICE_FILE = 1,
        WTD_CHOICE_CATALOG = 2,
        WTD_CHOICE_BLOB = 3,
        WTD_CHOICE_SIGNER = 4,
        WTD_CHOICE_CERT = 5
    }

    internal enum WinTrustStateAction : uint
    {
        WTD_STATEACTION_IGNORE = 0x00000000,
        WTD_STATEACTION_VERIFY = 0x00000001,
        WTD_STATEACTION_CLOSE = 0x00000002,
        WTD_STATEACTION_AUTO_CACHE = 0x00000003,
        WTD_STATEACTION_AUTO_CACHE_FLUSH = 0x00000004,
    }

    [type: Flags]
    internal enum WinTrustProviderFlags : uint
    {
        NONE = 0,
        WTD_USE_IE4_TRUST_FLAG = 0x00000001,
        WTD_NO_IE4_CHAIN_FLAG = 0x00000002,
        WTD_NO_POLICY_USAGE_FLAG = 0x00000004,
        WTD_REVOCATION_CHECK_NONE = 0x00000010,
        WTD_REVOCATION_CHECK_END_CERT = 0x00000020,
        WTD_REVOCATION_CHECK_CHAIN = 0x00000040,
        WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x00000080,
        WTD_SAFER_FLAG = 0x00000100,
        WTD_HASH_ONLY_FLAG = 0x00000200,
        WTD_USE_DEFAULT_OSVER_CHECK = 0x00000400,
        WTD_LIFETIME_SIGNING_FLAG = 0x00000800,
        WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000,
        WTD_DISABLE_MD2_MD4 = 0x00002000,
        WTD_MOTW = 0x00004000,
    }

    internal enum WinTrustUIContext : uint
    {
        WTD_UICONTEXT_EXECUTE = 0,
        WTD_UICONTEXT_INSTALL = 1,
    }
}
