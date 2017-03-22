using System;
using System.Security;

using Microsoft.Win32.SafeHandles;

namespace GostCryptography.Native
{
    /// <summary>
    /// Дескриптор ключа криптографического провайдера.
    /// </summary>
    [SecurityCritical]
    public sealed class SafeKeyHandleImpl : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeKeyHandleImpl()
            : base(true)
        {
        }

        public SafeKeyHandleImpl(IntPtr handle)
            : base(true)
        {
            SetHandle(handle);
        }

        public static SafeKeyHandleImpl InvalidHandle
        {
            get { return new SafeKeyHandleImpl(IntPtr.Zero); }
        }

        [SecurityCritical]
        protected override bool ReleaseHandle()
        {
            CryptoApi.CryptDestroyKey(handle);
            return true;
        }
    }
}