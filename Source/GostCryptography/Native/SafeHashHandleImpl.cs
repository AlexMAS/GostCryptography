using System;
using System.Security;

using Microsoft.Win32.SafeHandles;

namespace GostCryptography.Native
{
    /// <summary>
    /// Дескриптор функции хэширования криптографического провайдера.
    /// </summary>
    [SecurityCritical]
    public class SafeHashHandleImpl : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeHashHandleImpl()
            : base(true)
        {
        }

        public SafeHashHandleImpl(IntPtr handle)
            : base(true)
        {
            SetHandle(handle);
        }

        public static SafeHashHandleImpl InvalidHandle
        {
            get { return new SafeHashHandleImpl(IntPtr.Zero); }
        }

        [SecurityCritical]
        protected override bool ReleaseHandle()
        {
            CryptoApi.CryptDestroyHash(handle);
            return true;
        }
    }
}