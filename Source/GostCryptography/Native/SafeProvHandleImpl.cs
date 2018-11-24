using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;

using GostCryptography.Base;

using Microsoft.Win32.SafeHandles;

namespace GostCryptography.Native
{
	/// <summary>
	/// Дескриптор криптографического провайдера.
	/// </summary>
	[SecurityCritical]
	public sealed class SafeProvHandleImpl : SafeHandleZeroOrMinusOneIsInvalid
	{
		public static SafeProvHandleImpl InvalidHandle => new SafeProvHandleImpl(IntPtr.Zero);


		public SafeProvHandleImpl() : base(true)
		{
		}

		public SafeProvHandleImpl(IntPtr handle) : base(true)
		{
			SetHandle(handle);
		}

		public SafeProvHandleImpl(IntPtr handle, bool addref) : base(true)
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