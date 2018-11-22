using System;
using System.Security;
using System.Security.Permissions;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;
using GostCryptography.Native;

namespace GostCryptography.Gost_R3411
{
	/// <summary>
	/// Реализация Hash-based Message Authentication Code (HMAC) на базе алгоритма хэширования ГОСТ Р 34.11.
	/// </summary>
	public class Gost_R3411_HMAC : GostHMAC
	{
		/// <summary>
		/// Размер хэша.
		/// </summary>
		public const int DefaultHashSize = 256;

		/// <summary>
		/// Наименование алгоритма HMAC на базе ГОСТ Р 34.11.
		/// </summary>
		public const string AlgorithmNameValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:hmac-gostr3411";

		/// <summary>
		/// Устаревшее наименование алгоритма HMAC на базе ГОСТ Р 34.11.
		/// </summary>
		public const string ObsoleteAlgorithmNameValue = "http://www.w3.org/2001/04/xmldsig-more#hmac-gostr3411";

		/// <summary>
		/// Известные наименования алгоритма HMAC на базе ГОСТ Р 34.11.
		/// </summary>
		public static readonly string[] KnownAlgorithmNames = { AlgorithmNameValue, ObsoleteAlgorithmNameValue };


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_HMAC()
		{
			InitDefaults(new Gost_28147_89_SymmetricAlgorithm(ProviderType));
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_HMAC(ProviderTypes providerType) : base(providerType)
		{
			InitDefaults(new Gost_28147_89_SymmetricAlgorithm(ProviderType));
		}


		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="keyAlgorithm">Алгоритм для вычисления HMAC.</param>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		public Gost_R3411_HMAC(Gost_28147_89_SymmetricAlgorithmBase keyAlgorithm) : base(keyAlgorithm.ProviderType)
		{
			if (keyAlgorithm == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyAlgorithm));
			}

			InitDefaults(Gost_28147_89_SymmetricAlgorithm.CreateFromKey(keyAlgorithm));
		}


		private void InitDefaults(Gost_28147_89_SymmetricAlgorithm keyAlgorithm)
		{
			HashName = GetType().Name;
			HashSizeValue = DefaultHashSize;

			_keyAlgorithm = keyAlgorithm;
			_hashHandle = CryptoApiHelper.CreateHashHmac(keyAlgorithm.ProviderType, CryptoApiHelper.GetProviderHandle(keyAlgorithm.ProviderType), keyAlgorithm.InternalKeyHandle);
		}


		[SecurityCritical]
		private SafeHashHandleImpl _hashHandle;
		private Gost_28147_89_SymmetricAlgorithm _keyAlgorithm;


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