using System;

namespace AuthenticodeExaminer
{
    [Flags]
    public enum SignatureKind
    {
        NestedSignature = 0x1,
        Signature = 0x2,
        AuthenticodeTimestamp = 0x4,
        Rfc3161Timestamp = 0x8,
        AnySignature = NestedSignature | Signature,
        AnyCounterSignature = AuthenticodeTimestamp | Rfc3161Timestamp,
        Any = AnySignature | AnyCounterSignature
    }
}
