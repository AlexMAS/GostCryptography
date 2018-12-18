using System.Security;

using GostCryptography.Base;
using GostCryptography.Native;

namespace GostCryptography.Gost_R3411
{
	/// <summary>
	/// Базовый класс для всех реализаций алгоритма хэширования ГОСТ Р 34.11.
	/// </summary>
	public abstract class Gost_R3411_HashAlgorithm : GostHashAlgorithm, ISafeHandleProvider<SafeHashHandleImpl>
	{
		/// <inheritdoc />
		[SecuritySafeCritical]
		protected Gost_R3411_HashAlgorithm(int hashSize) : base(hashSize)
		{
			_hashHandle = CreateHashHandle();
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		protected Gost_R3411_HashAlgorithm(ProviderType providerType, int hashSize) : base(providerType, hashSize)
		{
			_hashHandle = CreateHashHandle();
		}

		[SecurityCritical]
		internal Gost_R3411_HashAlgorithm(ProviderType providerType, SafeProvHandleImpl providerHandle, int hashSize) : base(providerType, hashSize)
		{
			_hashHandle = CreateHashHandle(providerHandle);
		}


		/// <summary>
		/// Создает дескриптор функции хэширования криптографического провайдера.
		/// </summary>
		[SecurityCritical]
		protected SafeHashHandleImpl CreateHashHandle()
		{
			return CreateHashHandle(CryptoApiHelper.GetProviderHandle(ProviderType));
		}

		/// <summary>
		/// Создает дескриптор функции хэширования криптографического провайдера.
		/// </summary>
		[SecurityCritical]
		protected abstract SafeHashHandleImpl CreateHashHandle(SafeProvHandleImpl providerHandle);


		[SecurityCritical]
		private SafeHashHandleImpl _hashHandle;

		/// <inheritdoc />
		SafeHashHandleImpl ISafeHandleProvider<SafeHashHandleImpl>.SafeHandle
		{
			[SecurityCritical]
			get => _hashHandle;
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