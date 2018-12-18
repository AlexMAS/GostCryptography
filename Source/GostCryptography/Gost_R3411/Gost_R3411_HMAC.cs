using System;
using System.Security;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;
using GostCryptography.Native;

namespace GostCryptography.Gost_R3411
{
	/// <summary>
	/// Базовый класс для всех реализаций Hash-based Message Authentication Code (HMAC) на базе алгоритма хэширования ГОСТ Р 34.11.
	/// </summary>
	public abstract class Gost_R3411_HMAC<THash> : GostHMAC, ISafeHandleProvider<SafeHashHandleImpl> where THash : GostHashAlgorithm
	{
		/// <inheritdoc />
		[SecuritySafeCritical]
		protected Gost_R3411_HMAC(int hashSize) : base(hashSize)
		{
			InitDefaults(new Gost_28147_89_SymmetricAlgorithm(ProviderType));
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		protected Gost_R3411_HMAC(ProviderType providerType, int hashSize) : base(providerType, hashSize)
		{
			InitDefaults(new Gost_28147_89_SymmetricAlgorithm(ProviderType));
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="keyAlgorithm">Алгоритм для вычисления HMAC.</param>
		/// <param name="hashSize">Размер хэш-кода в битах.</param>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		protected Gost_R3411_HMAC(Gost_28147_89_SymmetricAlgorithmBase keyAlgorithm, int hashSize) : base(keyAlgorithm.ProviderType, hashSize)
		{
			if (keyAlgorithm == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyAlgorithm));
			}

			InitDefaults(Gost_28147_89_SymmetricAlgorithm.CreateFromKey(keyAlgorithm));
		}


		[SecuritySafeCritical]
		private void InitDefaults(Gost_28147_89_SymmetricAlgorithm keyAlgorithm)
		{
			HashName = typeof(THash).Name;

			_keyAlgorithm = keyAlgorithm;
			_hmacHandle = CreateHashHMAC(keyAlgorithm.ProviderType, CryptoApiHelper.GetProviderHandle(keyAlgorithm.ProviderType), keyAlgorithm.GetSafeHandle());
		}


		/// <summary>
		/// Создает дескриптор функции хэширования HMAC криптографического провайдера.
		/// </summary>
		[SecuritySafeCritical]
		protected abstract SafeHashHandleImpl CreateHashHMAC(ProviderType providerType, SafeProvHandleImpl providerHandle, SafeKeyHandleImpl symKeyHandle);


		[SecurityCritical]
		private SafeHashHandleImpl _hmacHandle;
		private Gost_28147_89_SymmetricAlgorithm _keyAlgorithm;


		/// <inheritdoc />
		SafeHashHandleImpl ISafeHandleProvider<SafeHashHandleImpl>.SafeHandle
		{
			[SecurityCritical]
			get { return _hmacHandle; }
		}


		/// <summary>
		/// Алгоритм для вычисления HMAC.
		/// </summary>
		public Gost_28147_89_SymmetricAlgorithmBase KeyAlgorithm
		{
			get
			{
				return _keyAlgorithm;
			}
			[SecuritySafeCritical]
			set
			{
				_keyAlgorithm = Gost_28147_89_SymmetricAlgorithm.CreateFromKey(value);
			}
		}

		/// <inheritdoc />
		public override byte[] Key
		{
			get
			{
				return _keyAlgorithm.Key;
			}
			set
			{
				_keyAlgorithm = new Gost_28147_89_SymmetricAlgorithm(ProviderType) { Key = value };

				Initialize();
			}
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override void Initialize()
		{
			var hmacHandle = CreateHashHMAC(ProviderType, CryptoApiHelper.GetProviderHandle(ProviderType), _keyAlgorithm.GetSafeHandle());
			_hmacHandle.TryDispose();
			_hmacHandle = hmacHandle;
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override void HashCore(byte[] data, int dataOffset, int dataLength)
		{
			CryptoApiHelper.HashData(_hmacHandle, data, dataOffset, dataLength);
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override byte[] HashFinal()
		{
			return CryptoApiHelper.EndHashData(_hmacHandle);
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				_keyAlgorithm?.Clear();
				_hmacHandle.TryDispose();
			}

			base.Dispose(disposing);
		}
	}
}