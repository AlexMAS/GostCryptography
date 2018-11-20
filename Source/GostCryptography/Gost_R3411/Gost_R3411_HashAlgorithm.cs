using System;
using System.Security;
using System.Security.Permissions;

using GostCryptography.Base;
using GostCryptography.Native;

namespace GostCryptography.Gost_R3411
{
	/// <summary>
	/// Базовый класс для всех реализаций алгоритма хэширования ГОСТ Р 34.11.
	/// </summary>
	public abstract class Gost_R3411_HashAlgorithm : GostHashAlgorithm
	{
		/// <inheritdoc />
		[SecuritySafeCritical]
		protected Gost_R3411_HashAlgorithm(int hashSize) : base(hashSize)
		{
			_hashHandle = CreateHashHandle();
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		protected Gost_R3411_HashAlgorithm(int providerType, int hashSize) : base(providerType, hashSize)
		{
			_hashHandle = CreateHashHandle();
		}


		/// <summary>
		/// Создает дескриптор функции хэширования криптографического провайдера.
		/// </summary>
		[SecuritySafeCritical]
		protected SafeHashHandleImpl CreateHashHandle()
		{
			return CreateHashHandle(CryptoApiHelper.GetProviderHandle(ProviderType));
		}

		/// <summary>
		/// Создает дескриптор функции хэширования криптографического провайдера.
		/// </summary>
		[SecuritySafeCritical]
		protected abstract SafeHashHandleImpl CreateHashHandle(SafeProvHandleImpl providerHandle);


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


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override void Initialize()
		{
			_hashHandle.TryDispose();
			_hashHandle = CreateHashHandle();
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override void HashCore(byte[] data, int dataOffset, int dataLength)
		{
			CryptoApiHelper.HashData(_hashHandle, data, dataOffset, dataLength);
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override byte[] HashFinal()
		{
			return CryptoApiHelper.EndHashData(_hashHandle);
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override void Dispose(bool disposing)
		{
			_hashHandle.TryDispose();

			base.Dispose(disposing);
		}
	}
}