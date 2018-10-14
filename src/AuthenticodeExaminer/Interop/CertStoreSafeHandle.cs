namespace AuthenticodeExaminer.Interop
{
    internal class CertStoreSafeHandle : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
    {
        static CertStoreSafeHandle()
        {
            InvalidHandle = new CertStoreSafeHandle();
            InvalidHandle.SetHandleAsInvalid();
        }

        public CertStoreSafeHandle() : base(true)
        {
        }

        public CertStoreSafeHandle(bool ownsHandle) : base(ownsHandle)
        {
        }

        public static CertStoreSafeHandle InvalidHandle { get; }

        protected override bool ReleaseHandle()
        {
            return Crypt32.CertCloseStore(handle, 0u);
        }
    }
}
