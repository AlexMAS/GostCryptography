using System;
using System.Security;
using System.Security.Permissions;

using GostCryptography.Native;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Реализация функции вычисления имитовставки по ГОСТ 28147.
	/// </summary>
	public class Gost28147ImitHashAlgorithm : Gost28147ImitHashAlgorithmBase
	{
		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost28147ImitHashAlgorithm()
		{
			_keyAlgorithm = new Gost28147SymmetricAlgorithm(ProviderType);
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost28147ImitHashAlgorithm(int providerType) : base(providerType)
		{
			_keyAlgorithm = new Gost28147SymmetricAlgorithm(ProviderType);
		}


		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="key">Ключ симметричного шифрования для подсчета имитовставки.</param>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		public Gost28147ImitHashAlgorithm(byte[] key)
		{
			if (key == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(key));
			}

			_keyAlgorithm = new Gost28147SymmetricAlgorithm(ProviderType) { Key = key };
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		/// <param name="key">Ключ симметричного шифрования для подсчета имитовставки.</param>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		public Gost28147ImitHashAlgorithm(int providerType, byte[] key) : base(providerType)
		{
			if (key == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(key));
			}

			_keyAlgorithm = new Gost28147SymmetricAlgorithm(ProviderType) { Key = key };
		}


		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="key">Ключ симметричного шифрования для подсчета имитовставки.</param>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		public Gost28147ImitHashAlgorithm(Gost28147SymmetricAlgorithmBase key) : base(key.ProviderType)
		{
			if (key == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(key));
			}

			KeyValue = null;

			_keyAlgorithm = Gost28147SymmetricAlgorithm.CreateFromKey(key);
		}


		[SecurityCritical]
		private Gost28147SymmetricAlgorithm _keyAlgorithm;

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


		/// <summary>
		/// Ключ симметричного шифрования.
		/// </summary>
		public override byte[] Key
		{
			get
			{
				return _keyAlgorithm.Key;
			}
			set
			{
				_keyAlgorithm.Key = value;
			}
		}

		/// <summary>
		/// Алгоритм симметричного шифрования ключа.
		/// </summary>
		public override Gost28147SymmetricAlgorithmBase KeyAlgorithm
		{
			[SecuritySafeCritical]
			get
			{
				return Gost28147SymmetricAlgorithm.CreateFromKey(_keyAlgorithm);
			}
			[SecuritySafeCritical]
			set
			{
				_keyAlgorithm = Gost28147SymmetricAlgorithm.CreateFromKey(value);
			}
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override void HashCore(byte[] data, int dataOffset, int dataLength)
		{
			if (_hashHandle == null)
			{
				InitHash();
			}

			CryptoApiHelper.HashData(_hashHandle, data, dataOffset, dataLength);
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override byte[] HashFinal()
		{
			if (_hashHandle == null)
			{
				InitHash();
			}

			return CryptoApiHelper.EndHashData(_hashHandle);
		}

		[SecurityCritical]
		private void InitHash()
		{
			var hProv = CryptoApiHelper.GetProviderHandle(ProviderType);
			var hHash = CryptoApiHelper.CreateHashImit(hProv, _keyAlgorithm.InternalKeyHandle);

			_hashHandle = hHash;
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public override void Initialize()
		{
			_hashHandle.TryDispose();
			_hashHandle = null;
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				_keyAlgorithm?.Clear();
				_hashHandle.TryDispose();
			}

			base.Dispose(disposing);
		}
	}
}