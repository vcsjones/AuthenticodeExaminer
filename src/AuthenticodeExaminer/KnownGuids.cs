using System;

namespace AuthenticodeExaminer
{
    internal static class KnownGuids
    {
        public static Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 { get; } = new Guid(0xaac56b, unchecked((short)0xcd44), 0x11d0, new byte[] { 0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee });
    }
}
