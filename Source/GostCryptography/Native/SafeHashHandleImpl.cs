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
		public static SafeHashHandleImpl InvalidHandle => new SafeHashHandleImpl(IntPtr.Zero);


		public SafeHashHandleImpl() : base(true)
		{
		}

		public SafeHashHandleImpl(IntPtr handle) : base(true)
		{
			SetHandle(handle);
		}


		[SecurityCritical]
		protected override bool ReleaseHandle()
		{
			CryptoApi.CryptDestroyHash(handle);
			return true;
		}
	}
}