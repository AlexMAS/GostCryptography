using System;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;

using GostCryptography.Native;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Реализация функции вычисления имитовставки по ГОСТ 28147.
	/// </summary>
	public sealed class Gost28147ImitHashAlgorithm : Gost28147ImitHashAlgorithmBase
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		[SecuritySafeCritical]
		public Gost28147ImitHashAlgorithm()
		{
			HashSizeValue = DefaultHashSize;

			_keyAlgorithm = new Gost28147SymmetricAlgorithm();
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="key">Ключ симметричного шифрования для подсчета имитовставки.</param>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		public Gost28147ImitHashAlgorithm(byte[] key)
			: this()
		{
			if (key == null)
			{
				throw ExceptionUtility.ArgumentNull("key");
			}

			_keyAlgorithm.Key = key;
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="key">Ключ симметричного шифрования для подсчета имитовставки.</param>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		public Gost28147ImitHashAlgorithm(Gost28147SymmetricAlgorithmBase key)
		{
			if (key == null)
			{
				throw ExceptionUtility.ArgumentNull("key");
			}

			KeyValue = null;
			HashSizeValue = DefaultHashSize;

			_keyAlgorithm = DuplicateKeyAlg(key);
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
				return DuplicateKeyAlg(_keyAlgorithm);
			}
			[SecuritySafeCritical]
			set
			{
				_keyAlgorithm = DuplicateKeyAlg(value);
			}
		}

		[SecurityCritical]
		private static Gost28147SymmetricAlgorithm DuplicateKeyAlg(SymmetricAlgorithm keyAlgorithm)
		{
			var sessionKey = keyAlgorithm as Gost28147SymmetricAlgorithm;

			return (sessionKey != null)
				? new Gost28147SymmetricAlgorithm(sessionKey.InternalProvHandle, sessionKey.InternalKeyHandle)
				: new Gost28147SymmetricAlgorithm { Key = keyAlgorithm.Key };
		}


		[SecuritySafeCritical]
		protected override void HashCore(byte[] data, int dataOffset, int dataLength)
		{
			if (_hashHandle == null)
			{
				InitHash();
			}

			CryptoApiHelper.HashData(_hashHandle, data, dataOffset, dataLength);
		}

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
			var hProv = CryptoApiHelper.ProviderHandle;
			var hHash = CryptoApiHelper.CreateHashImit(hProv, _keyAlgorithm.InternalKeyHandle);

			_hashHandle = hHash;
		}

		[SecuritySafeCritical]
		public override void Initialize()
		{
			_hashHandle.TryDispose();
			_hashHandle = null;
		}


		[SecuritySafeCritical]
		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				if (_keyAlgorithm != null)
				{
					_keyAlgorithm.Clear();
				}

				_hashHandle.TryDispose();
			}

			base.Dispose(disposing);
		}
	}
}