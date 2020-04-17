using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace GostCryptography.Native
{
    [SecurityCritical]
    class SafeStore : SafeHandleZeroOrMinusOneIsInvalid
    {
        public static SafeStore InvalidHandle => new SafeStore(IntPtr.Zero);


        public SafeStore() : base(true)
        {
        }

        public SafeStore(IntPtr handle) : base(true)
        {
            SetHandle(handle);
        }


        [SecurityCritical]
        protected override bool ReleaseHandle()
        {


            return true;
        }

        protected override void Dispose(bool disposing)
        {
            if (handle != IntPtr.Zero)
            {
                if (!CryptoApi.CertCloseStore(this, 0))
                {
                    var errCode = Marshal.GetLastWin32Error();
                    throw new SystemException(errCode.ToString("x"));
                }
            }
            base.Dispose(disposing);
        }
    }
}
