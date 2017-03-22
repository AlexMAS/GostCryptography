using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;

using Microsoft.Win32.SafeHandles;

namespace GostCryptography.Native
{
    /// <summary>
    /// Дескриптор криптографического провайдера.
    /// </summary>
    [SecurityCritical]
    public sealed class SafeProvHandleImpl : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeProvHandleImpl()
            : base(true)
        {
        }

        public SafeProvHandleImpl(IntPtr handle)
            : base(true)
        {
            SetHandle(handle);
        }

        public SafeProvHandleImpl(IntPtr handle, bool addref)
            : base(true)
        {
            if (!addref)
            {
                SetHandle(handle);
            }
            else
            {
                bool success;
                int errorCode;

                // Обеспечивает атомарность блока finally
                RuntimeHelpers.PrepareConstrainedRegions();
                try { }
                finally
                {
                    success = CryptoApi.CryptContextAddRef(handle, null, 0);
                    errorCode = Marshal.GetLastWin32Error();

                    if (success)
                    {
                        SetHandle(handle);
                    }
                }

                if (!success)
                {
                    throw ExceptionUtility.CryptographicException(errorCode);
                }
            }
        }

        public bool DeleteOnClose { get; set; }

        public static SafeProvHandleImpl InvalidHandle
        {
            get { return new SafeProvHandleImpl(IntPtr.Zero); }
        }

        [SecurityCritical]
        protected override bool ReleaseHandle()
        {
            if (DeleteOnClose)
            {
                CryptoApi.CryptSetProvParam2(handle, Constants.PP_DELETE_KEYSET, null, 0);
            }
            else
            {
                CryptoApi.CryptReleaseContext(handle, 0);
            }

            return true;
        }
    }
}