using AuthenticodeExaminer.Interop;
using System;
using System.Runtime.InteropServices;

namespace AuthenticodeExaminer
{

    internal static class FileSignatureVerifier
    {
        public static unsafe int IsFileSignatureValid(string file, RevocationChecking revocationChecking)
        {
            var pathPtr = Marshal.StringToHGlobalUni(file);
            try
            {
                var flags = WinTrustProviderFlags.NONE;
                var revocationFlags = WinTrustRevocationChecks.WTD_REVOKE_NONE;
                switch (revocationChecking)
                {
                    case RevocationChecking.None:
                        flags |= WinTrustProviderFlags.WTD_REVOCATION_CHECK_NONE;
                        break;
                    case RevocationChecking.Offline:
                        flags |= WinTrustProviderFlags.WTD_CACHE_ONLY_URL_RETRIEVAL;
                        goto default;
                    default:
                        flags |= WinTrustProviderFlags.WTD_REVOCATION_CHECK_CHAIN;
                        revocationFlags |= WinTrustRevocationChecks.WTD_REVOKE_WHOLECHAIN;
                        break;
                }
                var trust = stackalloc WINTRUST_DATA[1];
                var fileInfo = stackalloc WINTRUST_FILE_INFO[1];
                trust->cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>();
                trust->dwProvFlags = flags;
                trust->dwStateAction = WinTrustStateAction.WTD_STATEACTION_IGNORE;
                trust->dwUIChoice = WinTrustDataUIChoice.WTD_UI_NONE;
                trust->dwUIContext = WinTrustUIContext.WTD_UICONTEXT_EXECUTE;
                trust->dwUnionChoice = WinTrustUnionChoice.WTD_CHOICE_FILE;
                trust->fdwRevocationChecks = revocationFlags;
                trust->trustUnion = new WINTRUST_DATA_UNION
                {
                    pFile = fileInfo
                };
                trust->trustUnion.pFile->cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>();
                trust->trustUnion.pFile->pcwszFilePath = pathPtr;
                return Wintrust.WinVerifyTrustEx(new IntPtr(-1), KnownGuids.WINTRUST_ACTION_GENERIC_VERIFY_V2, trust);
            }
            finally
            {
                Marshal.FreeHGlobal(pathPtr);
            }
        }
    }
}
