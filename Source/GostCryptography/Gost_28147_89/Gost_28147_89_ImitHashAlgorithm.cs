using System;
using System.Security;

using GostCryptography.Base;
using GostCryptography.Native;

namespace GostCryptography.Gost_28147_89
{
	/// <summary>
	/// Реализация функции вычисления имитовставки по ГОСТ 28147-89.
	/// </summary>
	public class Gost_28147_89_ImitHashAlgorithm : Gost_28147_89_ImitHashAlgorithmBase, ISafeHandleProvider<SafeHashHandleImpl>
	{
		/// <summary>
		/// Размер имитовставки ГОСТ 28147-89.
		/// </summary>
		public const int DefaultHashSize = 32;

		/// <summary>
		/// Наименование алгоритма вычисления имитовставки ГОСТ 28147-89.
		/// </summary>
		public const string AlgorithmNameValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gost28147imit";

		/// <summary>
		/// Известные наименования алгоритма вычисления имитовставки ГОСТ 28147-89.
		/// </summary>
		public static readonly string[] KnownAlgorithmNames = { AlgorithmNameValue };


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_28147_89_ImitHashAlgorithm() : base(DefaultHashSize)
		{
			_keyAlgorithm = new Gost_28147_89_SymmetricAlgorithm(ProviderType);
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_28147_89_ImitHashAlgorithm(ProviderTypes providerType) : base(providerType, DefaultHashSize)
		{
			_keyAlgorithm = new Gost_28147_89_SymmetricAlgorithm(ProviderType);
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="key">Ключ симметричного шифрования для подсчета имитовставки.</param>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		public Gost_28147_89_ImitHashAlgorithm(Gost_28147_89_SymmetricAlgorithmBase key) : base(key.ProviderType, DefaultHashSize)
		{
			if (key == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(key));
			}

			KeyValue = null;

			_keyAlgorithm = Gost_28147_89_SymmetricAlgorithm.CreateFromKey(key);
		}


		[SecurityCritical]
		private Gost_28147_89_SymmetricAlgorithm _keyAlgorithm;

		[SecurityCritical]
		private SafeHashHandleImpl _hashHandle;


		/// <inheritdoc />
		public override string AlgorithmName => AlgorithmNameValue;


		/// <summary>
		/// Дескриптор функции хэширования.
		/// </summary>
		public SafeHashHandleImpl SafeHandle
		{
			[SecurityCritical]
			get { return _hashHandle; }
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
		public override Gost_28147_89_SymmetricAlgorithmBase KeyAlgorithm
		{
			[SecuritySafeCritical]
			get
			{
				return Gost_28147_89_SymmetricAlgorithm.CreateFromKey(_keyAlgorithm);
			}
			[SecuritySafeCritical]
			set
			{
				_keyAlgorithm = Gost_28147_89_SymmetricAlgorithm.CreateFromKey(value);
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