using System;
using System.Security;
using System.Security.Permissions;

using GostCryptography.Native;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Базовый класс для всех реализаций алгоритма хэширования ГОСТ Р 34.11.
	/// </summary>
	public abstract class Gost3411HashAlgorithmBase : GostHashAlgorithm
	{
		/// <inheritdoc />
		[SecuritySafeCritical]
		protected Gost3411HashAlgorithmBase(int hashSize) : base(hashSize)
		{
			_hashHandle = CreateHashHandle();
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		protected Gost3411HashAlgorithmBase(int providerType, int hashSize) : base(providerType, hashSize)
		{
			_hashHandle = CreateHashHandle();
		}


		/// <summary>
		/// Создает дескриптор функции хэширования криптографического провайдера.
		/// </summary>
		[SecuritySafeCritical]
		protected abstract SafeHashHandleImpl CreateHashHandle();


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