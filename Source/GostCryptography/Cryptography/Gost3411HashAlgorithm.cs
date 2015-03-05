using System;
using System.Security;
using System.Security.Permissions;

using GostCryptography.Native;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Реализация алгоритма хэширования по ГОСТ Р 34.11.
	/// </summary>
	public sealed class Gost3411HashAlgorithm : Gost3411HashAlgorithmBase
	{

		[SecuritySafeCritical]
		public Gost3411HashAlgorithm()
		{
			_hashHandle = CryptoApiHelper.CreateHash(CryptoApiHelper.ProviderHandle);
		}


		[SecurityCritical]
		private SafeHashHandleImpl _hashHandle;


		/// <summary>
		/// Приватный дескриптор функции хэширования.
		/// </summary>
		internal SafeHashHandleImpl InternalHashHandle
		{
			[SecurityCritical]
			get { return _hashHandle; }
		}

		/// <summary>
		/// Дескриптор функции хэширования.
		/// </summary>
		public IntPtr HashHandle
		{
			[SecurityCritical]
			[SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
			get { return InternalHashHandle.DangerousGetHandle(); }
		}


		[SecuritySafeCritical]
		public override void Initialize()
		{
			_hashHandle.TryDispose();
			_hashHandle = CryptoApiHelper.CreateHash(CryptoApiHelper.ProviderHandle);
		}

		[SecuritySafeCritical]
		protected override void HashCore(byte[] data, int dataOffset, int dataLength)
		{
			CryptoApiHelper.HashData(_hashHandle, data, dataOffset, dataLength);
		}

		[SecuritySafeCritical]
		protected override byte[] HashFinal()
		{
			return CryptoApiHelper.EndHashData(_hashHandle);
		}


		[SecuritySafeCritical]
		protected override void Dispose(bool disposing)
		{
			_hashHandle.TryDispose();

			base.Dispose(disposing);
		}
	}
}