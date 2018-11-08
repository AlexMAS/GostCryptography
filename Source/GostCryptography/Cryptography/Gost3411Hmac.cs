using System;
using System.Security;
using System.Security.Permissions;

using GostCryptography.Native;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Реализация Hash-based Message Authentication Code (HMAC) на базе алгоритма хэширования ГОСТ Р 34.11.
	/// </summary>
	public class Gost3411Hmac : GostHmac
	{
		public const int DefaultHashSize = 256;
		public const string DefaultHashName = GostCryptoConfig.DefaultHashName;


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost3411Hmac()
		{
			InitDefaults(new Gost28147SymmetricAlgorithm(ProviderType));
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost3411Hmac(int providerType) : base(providerType)
		{
			InitDefaults(new Gost28147SymmetricAlgorithm(ProviderType));
		}


		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="keyAlgorithm">Алгоритм для вычисления HMAC.</param>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		public Gost3411Hmac(Gost28147SymmetricAlgorithmBase keyAlgorithm) : base(keyAlgorithm.ProviderType)
		{
			if (keyAlgorithm == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyAlgorithm));
			}

			InitDefaults(Gost28147SymmetricAlgorithm.CreateFromKey(keyAlgorithm));
		}


		private void InitDefaults(Gost28147SymmetricAlgorithm keyAlgorithm)
		{
			HashName = DefaultHashName;
			HashSizeValue = DefaultHashSize;

			_keyAlgorithm = keyAlgorithm;
			_hashHandle = CryptoApiHelper.CreateHashHmac(keyAlgorithm.ProviderType, CryptoApiHelper.GetProviderHandle(keyAlgorithm.ProviderType), keyAlgorithm.InternalKeyHandle);
		}


		[SecurityCritical]
		private SafeHashHandleImpl _hashHandle;
		private Gost28147SymmetricAlgorithm _keyAlgorithm;


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
		/// Алгоритм для вычисления HMAC.
		/// </summary>
		public Gost28147SymmetricAlgorithmBase KeyAlgorithm
		{
			get
			{
				return _keyAlgorithm;
			}
			[SecuritySafeCritical]
			set
			{
				_keyAlgorithm = Gost28147SymmetricAlgorithm.CreateFromKey(value);
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
				_keyAlgorithm = new Gost28147SymmetricAlgorithm(ProviderType) { Key = value };

				Initialize();
			}
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override void Initialize()
		{
			var hashHmacHandle = CryptoApiHelper.CreateHashHmac(ProviderType, CryptoApiHelper.GetProviderHandle(ProviderType), _keyAlgorithm.InternalKeyHandle);
			_hashHandle.TryDispose();
			_hashHandle = hashHmacHandle;
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
			if (disposing)
			{
				_keyAlgorithm?.Clear();
				_hashHandle.TryDispose();
			}

			base.Dispose(disposing);
		}
	}
}