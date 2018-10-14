using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace AuthenticodeExaminer.Interop
{
    internal sealed class LocalBufferSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        [return: MarshalAs(UnmanagedType.SysInt)]
        [method: DllImport("kernel32.dll", EntryPoint = "LocalFree", CallingConvention = CallingConvention.Winapi, ExactSpelling = true)]
        private static extern IntPtr LocalFree
        (
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr hMem
        );


        [return: MarshalAs(UnmanagedType.SysInt)]
        [method: DllImport("kernel32.dll", EntryPoint = "LocalAlloc", CallingConvention = CallingConvention.Winapi, ExactSpelling = true)]
        private static extern IntPtr LocalAlloc
        (
            [param: In, MarshalAs(UnmanagedType.U2)] ushort uFlags,
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr uBytes
        );

        public LocalBufferSafeHandle(bool ownsHandle) : base(ownsHandle)
        {
        }

        public LocalBufferSafeHandle() : this(true)
        {
        }

        public static LocalBufferSafeHandle Zero
        {
            get
            {
                var instance = new LocalBufferSafeHandle(true);
                instance.SetHandle(IntPtr.Zero);
                return instance;
            }
        }

        public static LocalBufferSafeHandle Alloc(IntPtr size)
        {
            var instance = new LocalBufferSafeHandle(true);
            var handle = LocalAlloc(0, size);
            instance.SetHandle(handle);
            return instance;
        }

        public static LocalBufferSafeHandle Alloc(long size) => Alloc(new IntPtr(size));
        public static LocalBufferSafeHandle Alloc(int size) => Alloc(new IntPtr(size));

        protected override bool ReleaseHandle()
        {
            return IntPtr.Zero == LocalFree(handle);
        }
    }
}
