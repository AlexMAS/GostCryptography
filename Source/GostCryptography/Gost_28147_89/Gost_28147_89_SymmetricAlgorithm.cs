using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;

using GostCryptography.Asn1.Gost.Gost_28147_89;
using GostCryptography.Base;
using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Gost_28147_89
{
	/// <summary>
	/// Реализация алгоритма симметричного шифрования по ГОСТ 28147-89.
	/// </summary>
	public sealed class Gost_28147_89_SymmetricAlgorithm : Gost_28147_89_SymmetricAlgorithmBase, ISafeHandleProvider<SafeKeyHandleImpl>
	{
		/// <summary>
		/// Наименование алгоритма шифрования ГОСТ 28147-89.
		/// </summary>
		public const string AlgorithmNameValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gost28147";

		/// <summary>
		/// Известные наименования алгоритма шифрования ГОСТ 28147-89.
		/// </summary>
		public static readonly string[] KnownAlgorithmNames = { AlgorithmNameValue };


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_28147_89_SymmetricAlgorithm()
		{
			InitDefaults();
			_providerHandle = CryptoApiHelper.GetProviderHandle(ProviderType).DangerousAddRef();
			_keyHandle = SafeKeyHandleImpl.InvalidHandle;
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_28147_89_SymmetricAlgorithm(ProviderType providerType) : base(providerType)
		{
			InitDefaults();
			_providerHandle = CryptoApiHelper.GetProviderHandle(ProviderType).DangerousAddRef();
			_keyHandle = SafeKeyHandleImpl.InvalidHandle;
		}


		[SecurityCritical]
		internal Gost_28147_89_SymmetricAlgorithm(ProviderType providerType, SafeProvHandleImpl providerHandle, SafeKeyHandleImpl keyHandle) : base(providerType)
		{
			InitDefaults();
			_providerHandle = providerHandle.DangerousAddRef();
			_keyHandle = CryptoApiHelper.DuplicateKey(keyHandle);

			if (CryptoApiHelper.GetKeyParameterInt32(_keyHandle, Constants.KP_ALGID) != Constants.CALG_G28147)
			{
				throw ExceptionUtility.Argument(nameof(keyHandle), Resources.RequiredGost28147);
			}
		}


		[SecurityCritical]
		private void InitDefaults()
		{
			Mode = CipherMode.CFB;
			Padding = PaddingMode.None;
		}


		/// <inheritdoc />
		public override string AlgorithmName => AlgorithmNameValue;


		/// <summary>
		/// Создает экземпляр <see cref="Gost_28147_89_SymmetricAlgorithm"/> на основе указанного алгоритма шифрования.
		/// </summary>
		/// <param name="keyAlgorithm">Алгоритм симметричного шифрования ключа.</param>
		[SecurityCritical]
		public static Gost_28147_89_SymmetricAlgorithm CreateFromKey(Gost_28147_89_SymmetricAlgorithmBase keyAlgorithm)
		{
			if (keyAlgorithm == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyAlgorithm));
			}

			return (keyAlgorithm is Gost_28147_89_SymmetricAlgorithm sessionKey)
				? new Gost_28147_89_SymmetricAlgorithm(keyAlgorithm.ProviderType, sessionKey._providerHandle, sessionKey.GetSafeHandle())
				: new Gost_28147_89_SymmetricAlgorithm(keyAlgorithm.ProviderType) { Key = keyAlgorithm.Key };
		}

		/// <summary>
		/// Создает экземпляр <see cref="Gost_28147_89_SymmetricAlgorithm"/> на основе указанного пароля.
		/// </summary>
		[SecuritySafeCritical]
		public static Gost_28147_89_SymmetricAlgorithm CreateFromPassword(HashAlgorithm hashAlgorithm, byte[] password)
		{
			if (hashAlgorithm == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(hashAlgorithm));
			}

			if (!(hashAlgorithm is IGostAlgorithm gostHashAlgorithm))
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(hashAlgorithm));
			}

			if (!(hashAlgorithm is ISafeHandleProvider<SafeHashHandleImpl> hashHandleProvider))
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(hashAlgorithm));
			}

			if (password == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(password));
			}

			hashAlgorithm.TransformBlock(password, 0, password.Length, password, 0);

			var providerType = gostHashAlgorithm.ProviderType;
			var providerHandle = CryptoApiHelper.GetProviderHandle(providerType);
			var symKeyHandle = CryptoApiHelper.DeriveSymKey(providerHandle, hashHandleProvider.SafeHandle);

			return new Gost_28147_89_SymmetricAlgorithm(providerType, providerHandle, symKeyHandle);
		}

		/// <summary>
		/// Создает экземпляр <see cref="Gost_28147_89_SymmetricAlgorithm"/> на основе сессионного ключа.
		/// </summary>
		[SecuritySafeCritical]
		public static Gost_28147_89_SymmetricAlgorithm CreateFromSessionKey(ProviderType providerType, byte[] sessionKey)
		{
			if (sessionKey == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(sessionKey));
			}

			if (sessionKey.Length != 32)
			{
				throw ExceptionUtility.Argument(nameof(sessionKey), Resources.InvalidHashSize, 32);
			}

			var providerHandle = CryptoApiHelper.GetProviderHandle(providerType);
			var randomNumberGenerator = CryptoApiHelper.GetRandomNumberGenerator(providerType);

			using (var keyHandle = CryptoApiHelper.ImportBulkSessionKey(providerType, providerHandle, sessionKey, randomNumberGenerator))
			{
				return new Gost_28147_89_SymmetricAlgorithm(providerType, providerHandle, keyHandle);
			}
		}


		[SecurityCritical]
		private SafeProvHandleImpl _providerHandle;

		[SecurityCritical]
		private SafeKeyHandleImpl _keyHandle;


		/// <inheritdoc />
		SafeKeyHandleImpl ISafeHandleProvider<SafeKeyHandleImpl>.SafeHandle
		{
			[SecurityCritical]
			get
			{
				if (_keyHandle.IsInvalid)
				{
					GenerateKey();
				}

				return _keyHandle;
			}
		}


		/// <inheritdoc />
		public override byte[] Key
		{
			[SecuritySafeCritical]
			get { throw ExceptionUtility.NotSupported(Resources.SymmetryExportBulkKeyNotSupported); }
			[SecuritySafeCritical]
			set { throw ExceptionUtility.NotSupported(Resources.SymmetryImportBulkKeyNotSupported); }
		}

		/// <inheritdoc />
		public override int KeySize
		{
			[SecuritySafeCritical]
			get { return base.KeySize; }
			[SecuritySafeCritical]
			set
			{
				base.KeySize = value;

				_keyHandle.TryDispose();
				_providerHandle.TryDispose();

				_keyHandle = SafeKeyHandleImpl.InvalidHandle;
				_providerHandle = SafeProvHandleImpl.InvalidHandle;
			}
		}


		/// <summary>
		/// Создает симметричный ключ на основе пароля.
		/// </summary>
		[SecuritySafeCritical]
		public void DeriveFromPassword(GostHashAlgorithm hashAlgorithm, byte[] password)
		{
			var provider = CreateFromPassword(hashAlgorithm, password);

			_keyHandle.TryDispose();
			_providerHandle.TryDispose();

			_keyHandle = provider._keyHandle;
			_providerHandle = provider._providerHandle;

			provider._keyHandle = SafeKeyHandleImpl.InvalidHandle;
			provider._providerHandle = SafeProvHandleImpl.InvalidHandle;
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override byte[] ComputeHash(HashAlgorithm hash)
		{
			if (!(hash is ISafeHandleProvider<SafeHashHandleImpl> hashHadnleProvider))
			{
				throw ExceptionUtility.Argument(nameof(hash), Resources.RequiredGostHash);
			}

			var hashHandle = hashHadnleProvider.SafeHandle;

			CryptoApiHelper.HashKeyExchange(hashHandle, this.GetSafeHandle());

			return CryptoApiHelper.EndHashData(hashHandle);
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override void GenerateIV()
		{
			IVValue = new byte[DefaultIvSize];
			CryptoApiHelper.GetRandomNumberGenerator(ProviderType).GetBytes(IVValue);
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public override void GenerateKey()
		{
			_keyHandle = CryptoApiHelper.GenerateKey(_providerHandle, Constants.CALG_G28147, CspProviderFlags.NoFlags);

			KeyValue = null;
			KeySizeValue = DefaultKeySize;
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override ICryptoTransform CreateEncryptor()
		{
			var hKey = CryptoApiHelper.DuplicateKey(this.GetSafeHandle());

			return CreateCryptoTransform(hKey, IV, Gost_28147_89_CryptoTransformMode.Encrypt);
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public override ICryptoTransform CreateEncryptor(byte[] key, byte[] iv)
		{
			throw ExceptionUtility.NotSupported(Resources.Gost28147UnsafeCreateDecryptorNotSupported);
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override ICryptoTransform CreateDecryptor()
		{
			var hKey = CryptoApiHelper.DuplicateKey(this.GetSafeHandle());

			return CreateCryptoTransform(hKey, IV, Gost_28147_89_CryptoTransformMode.Decrypt);
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public override ICryptoTransform CreateDecryptor(byte[] key, byte[] iv)
		{
			throw ExceptionUtility.NotSupported(Resources.Gost28147UnsafeCreateDecryptorNotSupported);
		}


		[SecurityCritical]
		private ICryptoTransform CreateCryptoTransform(SafeKeyHandleImpl hKey, byte[] iv, Gost_28147_89_CryptoTransformMode transformMode)
		{
			// TODO: Refactor this!
			// NOTE: The params order is important!

			if (hKey == null)
			{
				hKey = CryptoApiHelper.GenerateKey(CryptoApiHelper.GetProviderHandle(ProviderType), Constants.CALG_G28147, CspProviderFlags.NoFlags);
			}

			var keyParameters = new Dictionary<int, object>();

			if (ModeValue == CipherMode.CTS)
			{
				throw ExceptionUtility.CryptographicException(Resources.CipherTextSteamingNotSupported);
			}

			if ((Padding != PaddingMode.None) && ((ModeValue == CipherMode.OFB) || (ModeValue == CipherMode.CFB)))
			{
				throw ExceptionUtility.CryptographicException(Resources.InvalidPaddingMode);
			}

			// Установка KP_MODE
			keyParameters.Add(Constants.KP_MODE, ModeValue);

			// Установка KP_PADDING
			keyParameters.Add(Constants.KP_PADDING, Constants.ZERO_PADDING);

			if ((ModeValue == CipherMode.CFB) && (FeedbackSizeValue != DefaultFeedbackSize))
			{
				throw ExceptionUtility.CryptographicException(Resources.IncorrectFeedbackSize);
			}

			// Установка KP_IV
			if (ModeValue != CipherMode.ECB)
			{
				if (iv == null)
				{
					iv = new byte[DefaultIvSize];
					CryptoApiHelper.GetRandomNumberGenerator(ProviderType).GetBytes(iv);
				}

				if (iv.Length < DefaultIvSize)
				{
					throw ExceptionUtility.CryptographicException(Resources.InvalidIvSize);
				}

				keyParameters.Add(Constants.KP_IV, iv);
			}

			return new Gost_28147_89_CryptoTransform(ProviderType, hKey, keyParameters, PaddingValue, ModeValue, BlockSizeValue, transformMode);
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override SymmetricAlgorithm DecodePrivateKey(byte[] encodedKeyExchangeData, GostKeyExchangeExportMethod keyExchangeExportMethod)
		{
			if (encodedKeyExchangeData == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(encodedKeyExchangeData));
			}

			int keyExchangeExportAlgId;

			if (keyExchangeExportMethod == GostKeyExchangeExportMethod.GostKeyExport)
			{
				keyExchangeExportAlgId = Constants.CALG_SIMPLE_EXPORT;
			}
			else if (keyExchangeExportMethod == GostKeyExchangeExportMethod.CryptoProKeyExport)
			{
				keyExchangeExportAlgId = Constants.CALG_PRO_EXPORT;
			}
			else
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(keyExchangeExportMethod));
			}

			var providerHandle = CryptoApiHelper.GetProviderHandle(ProviderType);

			var keyExchangeInfo = new Gost_28147_89_KeyExchangeInfo();
			keyExchangeInfo.Decode(encodedKeyExchangeData);

			using (var keyHandle = CryptoApiHelper.DuplicateKey(this.GetSafeHandle()))
			{
				CryptoApiHelper.SetKeyExchangeExportAlgId(ProviderType, keyHandle, keyExchangeExportAlgId);

				var keyExchangeHandle = CryptoApiHelper.ImportKeyExchange(providerHandle, keyExchangeInfo, keyHandle);

				return new Gost_28147_89_SymmetricAlgorithm(ProviderType, providerHandle, keyExchangeHandle);
			}
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public override byte[] EncodePrivateKey(Gost_28147_89_SymmetricAlgorithmBase keyExchangeAlgorithm, GostKeyExchangeExportMethod keyExchangeExportMethod)
		{
			if (keyExchangeAlgorithm == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyExchangeAlgorithm));
			}

			int keyExchangeExportAlgId;

			if (keyExchangeExportMethod == GostKeyExchangeExportMethod.GostKeyExport)
			{
				keyExchangeExportAlgId = Constants.CALG_SIMPLE_EXPORT;
			}
			else if (keyExchangeExportMethod == GostKeyExchangeExportMethod.CryptoProKeyExport)
			{
				keyExchangeExportAlgId = Constants.CALG_PRO_EXPORT;
			}
			else
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(keyExchangeExportMethod));
			}

			var currentSessionKey = keyExchangeAlgorithm as Gost_28147_89_SymmetricAlgorithm;

			if (currentSessionKey == null)
			{
				using (var derivedSessionKey = new Gost_28147_89_SymmetricAlgorithm(ProviderType))
				{
					derivedSessionKey.Key = keyExchangeAlgorithm.Key;

					return EncodePrivateKeyInternal(derivedSessionKey, keyExchangeExportAlgId);
				}
			}

			return EncodePrivateKeyInternal(currentSessionKey, keyExchangeExportAlgId);
		}

		[SecurityCritical]
		private byte[] EncodePrivateKeyInternal(Gost_28147_89_SymmetricAlgorithm sessionKey, int keyExchangeExportAlgId)
		{
			var hSessionKey = sessionKey.GetSafeHandle();

			using (var keyHandle = CryptoApiHelper.DuplicateKey(this.GetSafeHandle()))
			{
				CryptoApiHelper.SetKeyExchangeExportAlgId(ProviderType, keyHandle, keyExchangeExportAlgId);
				CryptoApiHelper.SetKeyParameter(keyHandle, Constants.KP_IV, IV);

				var keyExchangeInfo = CryptoApiHelper.ExportKeyExchange(hSessionKey, keyHandle);

				return keyExchangeInfo.Encode();
			}
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override void Dispose(bool disposing)
		{
			_keyHandle.TryDispose();
			_providerHandle.TryDispose();

			base.Dispose(disposing);
		}
	}
}