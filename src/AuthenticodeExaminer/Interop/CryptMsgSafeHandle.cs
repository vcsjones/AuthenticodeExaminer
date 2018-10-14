namespace AuthenticodeExaminer.Interop
{
    internal class CryptMsgSafeHandle : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
    {

        static CryptMsgSafeHandle()
        {
            InvalidHandle = new CryptMsgSafeHandle(true);
            InvalidHandle.SetHandleAsInvalid();
        }

        public CryptMsgSafeHandle(bool ownsHandle) : base(ownsHandle)
        {
        }

        public CryptMsgSafeHandle() : base(true)
        {
        }

        public static CryptMsgSafeHandle InvalidHandle { get; }

        protected override bool ReleaseHandle()
        {
            return Crypt32.CryptMsgClose(handle);
        }
    }
}
