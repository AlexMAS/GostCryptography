using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;

using GostCryptography.Asn1.Common;
using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Реализация алгоритма симметричного шифрования по ГОСТ 28147.
	/// </summary>
	public sealed class Gost28147SymmetricAlgorithm : Gost28147SymmetricAlgorithmBase
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		[SecuritySafeCritical]
		public Gost28147SymmetricAlgorithm()
		{
			Mode = CipherMode.CFB;
			Padding = PaddingMode.None;

			_provHandle = SafeProvHandleImpl.InvalidHandle;
			_keyHandle = SafeKeyHandleImpl.InvalidHandle;
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="provHandle">Дескриптор криптографического провайдера.</param>
		/// <param name="keyHandle">Дескриптор ключа симметричного шифрования.</param>
		/// <exception cref="ArgumentException"></exception>
		[SecurityCritical]
		[SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		public Gost28147SymmetricAlgorithm(IntPtr provHandle, IntPtr keyHandle)
			: this()
		{
			_provHandle = new SafeProvHandleImpl(provHandle, true);
			_keyHandle = CryptoApiHelper.DuplicateKey(keyHandle);

			if (CryptoApiHelper.GetKeyParameterInt32(_keyHandle, Constants.KP_ALGID) != Constants.CALG_G28147)
			{
				throw ExceptionUtility.Argument("keyHandle", Resources.RequiredGost28147);
			}
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="provHandle">Дескриптор криптографического провайдера.</param>
		/// <param name="keyHandle">Дескриптор ключа симметричного шифрования.</param>
		/// <exception cref="ArgumentException"></exception>
		[SecurityCritical]
		internal Gost28147SymmetricAlgorithm(SafeProvHandleImpl provHandle, SafeKeyHandleImpl keyHandle)
			: this()
		{
			_provHandle = provHandle.DangerousAddRef();
			_keyHandle = CryptoApiHelper.DuplicateKey(keyHandle);

			if (CryptoApiHelper.GetKeyParameterInt32(_keyHandle, Constants.KP_ALGID) != Constants.CALG_G28147)
			{
				throw ExceptionUtility.Argument("keyHandle", Resources.RequiredGost28147);
			}
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
			get
			{
				throw ExceptionUtility.NotSupported(Resources.SymmetryExportBulkKeyNotSupported);
			}
			[SecuritySafeCritical]
			set
			{
				throw ExceptionUtility.NotSupported(Resources.SymmetryImportBulkKeyNotSupported);
			}
		}

		/// <summary>
		/// Размер ключа симметричного шифрования.
		/// </summary>
		public override int KeySize
		{
			[SecuritySafeCritical]
			get
			{
				return base.KeySize;
			}
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
		public void DeriveFromPassword(byte[] password)
		{
			var provider = CreateFromPassword(password);

			_keyHandle.TryDispose();
			_provHandle.TryDispose();

			_keyHandle = provider._keyHandle;
			_provHandle = provider._provHandle;

			provider._keyHandle = SafeKeyHandleImpl.InvalidHandle;
			provider._provHandle = SafeProvHandleImpl.InvalidHandle;
		}

		/// <summary>
		/// Создает симметричный ключ на основе пароля.
		/// </summary>
		[SecuritySafeCritical]
		public static Gost28147SymmetricAlgorithm CreateFromPassword(byte[] password)
		{
			if (password == null)
			{
				throw ExceptionUtility.ArgumentNull("password");
			}

			var providerHandle = CryptoApiHelper.ProviderHandle;

			var hashHandle = CryptoApiHelper.CreateHash_3411_94(providerHandle);
			CryptoApiHelper.HashData(hashHandle, password, 0, password.Length);

			var symKeyHandle = CryptoApiHelper.DeriveSymKey(providerHandle, hashHandle);
			return new Gost28147SymmetricAlgorithm(providerHandle, symKeyHandle);
		}


		/// <summary>
		/// Хэширует секретный ключ.
		/// </summary>
		/// <exception cref="ArgumentException"></exception>
		[SecuritySafeCritical]
		public override byte[] ComputeHash(HashAlgorithm hash)
		{
			SafeHashHandleImpl hashHandle;

			if (hash is Gost3411HashAlgorithm)
			{
				hashHandle = ((Gost3411HashAlgorithm)hash).InternalHashHandle;
			}
			else if (hash is Gost3411Hmac)
			{
				hashHandle = ((Gost3411Hmac)hash).InternalHashHandle;
			}
			else if (hash is Gost28147ImitHashAlgorithm)
			{
				hashHandle = ((Gost28147ImitHashAlgorithm)hash).InternalHashHandle;
			}
			else
			{
				throw ExceptionUtility.Argument("hash", Resources.RequiredGostHash);
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
			CryptoApiHelper.RandomNumberGenerator.GetBytes(IVValue);
		}

		/// <summary>
		/// Генерация случайного ключа.
		/// </summary>
		[SecuritySafeCritical]
		public override void GenerateKey()
		{
			_provHandle = CryptoApiHelper.ProviderHandle.DangerousAddRef();
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

			return CreateCryptoTransform(hKey, IV, Gost28147CryptoTransformMode.Encrypt);
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

			return CreateCryptoTransform(hKey, IV, Gost28147CryptoTransformMode.Decrypt);
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
		private ICryptoTransform CreateCryptoTransform(SafeKeyHandleImpl hKey, byte[] iv, Gost28147CryptoTransformMode transformMode)
		{
			if (hKey == null)
			{
				hKey = CryptoApiHelper.GenerateKey(CryptoApiHelper.ProviderHandle, Constants.CALG_G28147, CspProviderFlags.NoFlags);
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
					CryptoApiHelper.RandomNumberGenerator.GetBytes(iv);
				}

				if (iv.Length < DefaultIvSize)
				{
					throw ExceptionUtility.CryptographicException(Resources.InvalidIvSize);
				}

				keyParameters.Add(Constants.KP_IV, iv);
			}

			return new Gost28147CryptoTransform(hKey, keyParameters, PaddingValue, ModeValue, BlockSizeValue, transformMode);
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
				throw ExceptionUtility.ArgumentNull("encodedKeyExchangeData");
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
				throw ExceptionUtility.ArgumentOutOfRange("keyExchangeExportMethod");
			}

			var providerHandle = CryptoApiHelper.ProviderHandle;

			var keyExchangeInfo = new GostKeyExchangeInfo();
			keyExchangeInfo.Decode(encodedKeyExchangeData);

			using (var keyHandle = CryptoApiHelper.DuplicateKey(InternalKeyHandle))
			{
				CryptoApiHelper.SetKeyParameterInt32(keyHandle, Constants.KP_ALGID, keyExchangeExportAlgId);

				var keyExchangeHandle = CryptoApiHelper.ImportKeyExchange(providerHandle, keyExchangeInfo, keyHandle);

				return new Gost28147SymmetricAlgorithm(providerHandle, keyExchangeHandle);
			}
		}

		/// <summary>
		/// Экспортирует (шифрует) секретный ключ.
		/// </summary>
		/// <param name="keyExchangeAlgorithm">Алгоритм симметричного шифрования.</param>
		/// <param name="keyExchangeExportMethod">Алгоритм экспорта ключа.</param>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		public override byte[] EncodePrivateKey(Gost28147SymmetricAlgorithmBase keyExchangeAlgorithm, GostKeyExchangeExportMethod keyExchangeExportMethod)
		{
			if (keyExchangeAlgorithm == null)
			{
				throw ExceptionUtility.ArgumentNull("keyExchangeAlgorithm");
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
				throw ExceptionUtility.ArgumentOutOfRange("keyExchangeExportMethod");
			}

			var currentSessionKey = keyExchangeAlgorithm as Gost28147SymmetricAlgorithm;

			if (currentSessionKey == null)
			{
				using (var derivedSessinKey = new Gost28147SymmetricAlgorithm())
				{
					derivedSessinKey.Key = keyExchangeAlgorithm.Key;

					return EncodePrivateKeyInternal(derivedSessinKey, keyExchangeExportAlgId);
				}
			}

			return EncodePrivateKeyInternal(currentSessionKey, keyExchangeExportAlgId);
		}

		[SecurityCritical]
		private byte[] EncodePrivateKeyInternal(Gost28147SymmetricAlgorithm sessionKey, int keyExchangeExportAlgId)
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


		[SecuritySafeCritical]
		protected override void Dispose(bool disposing)
		{
			_keyHandle.TryDispose();
			_provHandle.TryDispose();

			base.Dispose(disposing);
		}
	}
}