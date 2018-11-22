using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;

using GostCryptography.Asn1.Gost.Gost_28147_89;
using GostCryptography.Base;
using GostCryptography.Gost_R3411;
using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Gost_28147_89
{
	/// <summary>
	/// Реализация алгоритма симметричного шифрования по ГОСТ 28147-89.
	/// </summary>
	public class Gost_28147_89_SymmetricAlgorithm : Gost_28147_89_SymmetricAlgorithmBase
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
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_28147_89_SymmetricAlgorithm(ProviderTypes providerType) : base(providerType)
		{
			InitDefaults();
		}


		[SecurityCritical]
		internal Gost_28147_89_SymmetricAlgorithm(ProviderTypes providerType, SafeProvHandleImpl provHandle, SafeKeyHandleImpl keyHandle) : base(providerType)
		{
			_provHandle = provHandle.DangerousAddRef();
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

			_provHandle = SafeProvHandleImpl.InvalidHandle;
			_keyHandle = SafeKeyHandleImpl.InvalidHandle;
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
				? new Gost_28147_89_SymmetricAlgorithm(keyAlgorithm.ProviderType, sessionKey.InternalProvHandle, sessionKey.InternalKeyHandle)
				: new Gost_28147_89_SymmetricAlgorithm(keyAlgorithm.ProviderType) { Key = keyAlgorithm.Key };
		}

		/// <summary>
		/// Создает экземпляр <see cref="Gost_28147_89_SymmetricAlgorithm"/> на основе указанного пароля.
		/// </summary>
		[SecuritySafeCritical]
		public static Gost_28147_89_SymmetricAlgorithm CreateFromPassword(GostHashAlgorithm hashAlgorithm, byte[] password)
		{
			if (hashAlgorithm == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(hashAlgorithm));
			}

			if (!(hashAlgorithm is Gost_R3411_HashAlgorithm))
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(hashAlgorithm));
			}

			if (password == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(password));
			}

			var gostHashAlgorithm = (Gost_R3411_HashAlgorithm)hashAlgorithm;
			gostHashAlgorithm.TransformBlock(password, 0, password.Length, password, 0);

			var providerType = gostHashAlgorithm.ProviderType;
			var providerHandle = CryptoApiHelper.GetProviderHandle(providerType);
			var symKeyHandle = CryptoApiHelper.DeriveSymKey(providerHandle, gostHashAlgorithm.InternalHashHandle);

			return new Gost_28147_89_SymmetricAlgorithm(providerType, providerHandle, symKeyHandle);
		}


		[SecurityCritical]
		private SafeProvHandleImpl _provHandle;

		[SecurityCritical]
		private SafeKeyHandleImpl _keyHandle;


		/// <summary>
		/// Приватный дескриптор провайдера.
		/// </summary>
		internal SafeProvHandleImpl InternalProvHandle
		{
			[SecurityCritical]
			get
			{
				if (_keyHandle.IsInvalid)
				{
					GenerateKey();
				}

				return _provHandle;
			}
		}

		/// <summary>
		/// Дескрипор провайдера.
		/// </summary>
		public IntPtr ProviderHandle
		{
			[SecurityCritical]
			[SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
			get { return InternalProvHandle.DangerousGetHandle(); }
		}


		/// <summary>
		/// Приватный дескриптор ключа симметричного шифрования.
		/// </summary>
		internal SafeKeyHandleImpl InternalKeyHandle
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

		/// <summary>
		/// Дескриптор ключа симметричного шифрования.
		/// </summary>
		public IntPtr KeyHandle
		{
			[SecurityCritical]
			[SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
			get { return InternalKeyHandle.DangerousGetHandle(); }
		}


		/// <summary>
		/// Ключ симметричного шифрования.
		/// </summary>
		/// <remarks>
		/// Если ключ не был задан, то при получении ключа он будет сгенерирован функцией <see cref="GenerateKey()"/>.
		/// </remarks>
		public override byte[] Key
		{
			[SecuritySafeCritical]
			get { throw ExceptionUtility.NotSupported(Resources.SymmetryExportBulkKeyNotSupported); }
			[SecuritySafeCritical]
			set { throw ExceptionUtility.NotSupported(Resources.SymmetryImportBulkKeyNotSupported); }
		}

		/// <summary>
		/// Размер ключа симметричного шифрования.
		/// </summary>
		public override int KeySize
		{
			[SecuritySafeCritical]
			get { return base.KeySize; }
			[SecuritySafeCritical]
			set
			{
				base.KeySize = value;

				_keyHandle.TryDispose();
				_provHandle.TryDispose();

				_keyHandle = SafeKeyHandleImpl.InvalidHandle;
				_provHandle = SafeProvHandleImpl.InvalidHandle;
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
			_provHandle.TryDispose();

			_keyHandle = provider._keyHandle;
			_provHandle = provider._provHandle;

			provider._keyHandle = SafeKeyHandleImpl.InvalidHandle;
			provider._provHandle = SafeProvHandleImpl.InvalidHandle;
		}


		/// <summary>
		/// Хэширует секретный ключ.
		/// </summary>
		/// <exception cref="ArgumentException"></exception>
		[SecuritySafeCritical]
		public override byte[] ComputeHash(HashAlgorithm hash)
		{
			SafeHashHandleImpl hashHandle;

			switch (hash)
			{
				case Gost_R3411_94_HashAlgorithm hashAlgorithm:
					hashHandle = hashAlgorithm.InternalHashHandle;
					break;
				case Gost_R3411_HMAC hmacHashAlgorithm:
					hashHandle = hmacHashAlgorithm.InternalHashHandle;
					break;
				case Gost_28147_89_ImitHashAlgorithm imitHashAlgorithm:
					hashHandle = imitHashAlgorithm.InternalHashHandle;
					break;
				default:
					throw ExceptionUtility.Argument(nameof(hash), Resources.RequiredGostHash);
			}

			CryptoApiHelper.HashKeyExchange(hashHandle, InternalKeyHandle);

			return CryptoApiHelper.EndHashData(hashHandle);
		}


		/// <summary>
		/// Генерация случайной синхропосылки.
		/// </summary>
		[SecuritySafeCritical]
		public override void GenerateIV()
		{
			IVValue = new byte[DefaultIvSize];
			CryptoApiHelper.GetRandomNumberGenerator(ProviderType).GetBytes(IVValue);
		}

		/// <summary>
		/// Генерация случайного ключа.
		/// </summary>
		[SecuritySafeCritical]
		public override void GenerateKey()
		{
			_provHandle = CryptoApiHelper.GetProviderHandle(ProviderType).DangerousAddRef();
			_keyHandle = CryptoApiHelper.GenerateKey(_provHandle, Constants.CALG_G28147, CspProviderFlags.NoFlags);

			KeyValue = null;
			KeySizeValue = DefaultKeySize;
		}


		/// <summary>
		/// Создание объекта криптографического преобразования (шифратора).
		/// </summary>
		[SecuritySafeCritical]
		public override ICryptoTransform CreateEncryptor()
		{
			var hKey = CryptoApiHelper.DuplicateKey(InternalKeyHandle);

			return CreateCryptoTransform(hKey, IV, Gost_28147_89_CryptoTransformMode.Encrypt);
		}

		/// <summary>
		/// Создание объекта криптографического преобразования (шифратора) с заданным ключом и синхропосылкой.
		/// </summary>
		/// <exception cref="NotSupportedException"></exception>
		[SecuritySafeCritical]
		public override ICryptoTransform CreateEncryptor(byte[] key, byte[] iv)
		{
			throw ExceptionUtility.NotSupported(Resources.Gost28147UnsafeCreateDecryptorNotSupported);
		}


		/// <summary>
		/// Создание объекта криптографического преобразования (дешифратора).
		/// </summary>
		[SecuritySafeCritical]
		public override ICryptoTransform CreateDecryptor()
		{
			var hKey = CryptoApiHelper.DuplicateKey(InternalKeyHandle);

			return CreateCryptoTransform(hKey, IV, Gost_28147_89_CryptoTransformMode.Decrypt);
		}

		/// <summary>
		/// Создание объекта криптографического преобразования (дешифратора) с заданным ключом и синхропосылкой.
		/// </summary>
		/// <exception cref="NotSupportedException"></exception>
		[SecuritySafeCritical]
		public override ICryptoTransform CreateDecryptor(byte[] key, byte[] iv)
		{
			throw ExceptionUtility.NotSupported(Resources.Gost28147UnsafeCreateDecryptorNotSupported);
		}


		[SecurityCritical]
		private ICryptoTransform CreateCryptoTransform(SafeKeyHandleImpl hKey, byte[] iv, Gost_28147_89_CryptoTransformMode transformMode)
		{
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

			// Установка KP_PADDING
			keyParameters.Add(Constants.KP_PADDING, Constants.ZERO_PADDING);

			if ((ModeValue == CipherMode.CFB) && (FeedbackSizeValue != DefaultFeedbackSize))
			{
				throw ExceptionUtility.CryptographicException(Resources.IncorrectFeedbackSize);
			}

			// Установка KP_MODE
			keyParameters.Add(Constants.KP_MODE, ModeValue);

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


		/// <summary>
		/// Импортирует (дешифрует) секретный ключ.
		/// </summary>
		/// <param name="encodedKeyExchangeData">Зашифрованный секретный ключ.</param>
		/// <param name="keyExchangeExportMethod">Алгоритм экспорта общего секретного ключа.</param>
		/// <exception cref="ArgumentNullException"></exception>
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

			using (var keyHandle = CryptoApiHelper.DuplicateKey(InternalKeyHandle))
			{
				CryptoApiHelper.SetKeyParameterInt32(keyHandle, Constants.KP_ALGID, keyExchangeExportAlgId);

				var keyExchangeHandle = CryptoApiHelper.ImportKeyExchange(providerHandle, keyExchangeInfo, keyHandle);

				return new Gost_28147_89_SymmetricAlgorithm(ProviderType, providerHandle, keyExchangeHandle);
			}
		}

		/// <summary>
		/// Экспортирует (шифрует) секретный ключ.
		/// </summary>
		/// <param name="keyExchangeAlgorithm">Алгоритм симметричного шифрования.</param>
		/// <param name="keyExchangeExportMethod">Алгоритм экспорта ключа.</param>
		/// <exception cref="ArgumentNullException"></exception>
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
				using (var derivedSessinKey = new Gost_28147_89_SymmetricAlgorithm(ProviderType))
				{
					derivedSessinKey.Key = keyExchangeAlgorithm.Key;

					return EncodePrivateKeyInternal(derivedSessinKey, keyExchangeExportAlgId);
				}
			}

			return EncodePrivateKeyInternal(currentSessionKey, keyExchangeExportAlgId);
		}

		[SecurityCritical]
		private byte[] EncodePrivateKeyInternal(Gost_28147_89_SymmetricAlgorithm sessionKey, int keyExchangeExportAlgId)
		{
			var hSessionKey = sessionKey.InternalKeyHandle;

			using (var keyHandle = CryptoApiHelper.DuplicateKey(InternalKeyHandle))
			{
				CryptoApiHelper.SetKeyParameterInt32(keyHandle, Constants.KP_ALGID, keyExchangeExportAlgId);
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
			_provHandle.TryDispose();

			base.Dispose(disposing);
		}
	}
}