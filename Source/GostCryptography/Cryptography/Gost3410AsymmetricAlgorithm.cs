using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;

using GostCryptography.Asn1.Common;
using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Реализация алгоритма ГОСТ Р 34.10.
	/// </summary>
	[SecurityCritical]
	[SecuritySafeCritical]
	public sealed class Gost3410AsymmetricAlgorithm : Gost3410AsymmetricAlgorithmBase, ICspAsymmetricAlgorithm
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		[SecuritySafeCritical]
		[ReflectionPermission(SecurityAction.Assert, MemberAccess = true)]
		public Gost3410AsymmetricAlgorithm()
			: this(null)
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerParameters">Параметры криптографического провайдера.</param>
		[SecuritySafeCritical]
		public Gost3410AsymmetricAlgorithm(CspParameters providerParameters)
		{
			LegalKeySizesValue = DefaultLegalKeySizes;

			_providerParameters = CreateProviderParameters(providerParameters, CspProviderFlags.UseMachineKeyStore, out _isRandomKeyContainer);

			if (!_isRandomKeyContainer)
			{
				GetKeyPair();
			}
		}


		public const int DefaultKeySize = 512;
		public static readonly KeySizes[] DefaultLegalKeySizes = { new KeySizes(DefaultKeySize, DefaultKeySize, 0) };

		private readonly CspParameters _providerParameters;
		private readonly bool _isRandomKeyContainer;
		private bool _isPersistentKey;
		private bool _isPublicKeyOnly;


		[SecurityCritical]
		private SafeProvHandleImpl _providerHandle;

		[SecurityCritical]
		private volatile SafeKeyHandleImpl _keyHandle;


		/// <summary>
		/// Приватный дескриптор провайдера.
		/// </summary>
		internal SafeProvHandleImpl InternalProvHandle
		{
			[SecurityCritical]
			get
			{
				GetKeyPair();

				return _providerHandle;
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
		/// Приватный дескриптор ключа.
		/// </summary>
		internal SafeKeyHandleImpl InternalKeyHandle
		{
			[SecurityCritical]
			get
			{
				GetKeyPair();

				return _keyHandle;
			}
		}

		/// <summary>
		/// Дескриптор ключа.
		/// </summary>
		public IntPtr KeyHandle
		{
			[SecurityCritical]
			[SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
			get { return InternalKeyHandle.DangerousGetHandle(); }
		}

		/// <summary>
		/// Размер ключа.
		/// </summary>
		public override int KeySize
		{
			[SecuritySafeCritical]
			get
			{
				GetKeyPair();

				return DefaultKeySize;
			}
		}

		/// <summary>
		/// Хранить ключ в криптографическом провайдере.
		/// </summary>
		public bool IsPersistentKey
		{
			[SecuritySafeCritical]
			get
			{
				if (_providerHandle == null)
				{
					lock (this)
					{
						if (_providerHandle == null)
						{
							_providerHandle = CreateProviderHandle(_providerParameters, _isRandomKeyContainer);
						}
					}
				}

				return _isPersistentKey;
			}
			[SecuritySafeCritical]
			set
			{
				var currentValue = IsPersistentKey;

				if (currentValue != value)
				{
					var keyContainerPermission = new KeyContainerPermission(KeyContainerPermissionFlags.NoFlags);
					var containerAccessEntry = new KeyContainerPermissionAccessEntry(_providerParameters, value ? KeyContainerPermissionFlags.Create : KeyContainerPermissionFlags.Delete);
					keyContainerPermission.AccessEntries.Add(containerAccessEntry);
					keyContainerPermission.Demand();

					_isPersistentKey = value;
					_providerHandle.DeleteOnClose = !_isPersistentKey;
				}
			}
		}

		/// <summary>
		/// Имеется доступ только к открытому ключу.
		/// </summary>
		public bool IsPublicKeyOnly
		{
			[SecuritySafeCritical]
			get
			{
				GetKeyPair();

				return _isPublicKeyOnly;
			}
		}

		/// <summary>
		/// Информация о контейнере ключей.
		/// </summary>
		public CspKeyContainerInfo CspKeyContainerInfo
		{
			[SecuritySafeCritical]
			get
			{
				GetKeyPair();

				return CspKeyContainerInfoHelper.CreateCspKeyContainerInfo(_providerParameters, _isRandomKeyContainer);
			}
		}


		/// <summary>
		/// Экспортирует параметры алгоритма в BLOB.
		/// </summary>
		[SecuritySafeCritical]
		public byte[] ExportCspBlob(bool includePrivateParameters)
		{
			GetKeyPair();

			if (includePrivateParameters)
			{
				throw ExceptionUtility.CryptographicException(Resources.UserExportBulkBlob);
			}

			return CryptoApiHelper.ExportCspBlob(_keyHandle, SafeKeyHandleImpl.InvalidHandle, Constants.PUBLICKEYBLOB);
		}

		/// <summary>
		/// Импортирует параметры алгоритма в BLOB.
		/// </summary>
		/// <exception cref="ArgumentException"></exception>
		[SecuritySafeCritical]
		public void ImportCspBlob(byte[] importedKeyBytes)
		{
			if (importedKeyBytes == null)
			{
				throw ExceptionUtility.ArgumentNull("importedKeyBytes");
			}

			if (!IsPublicKeyBlob(importedKeyBytes))
			{
				throw ExceptionUtility.Argument("importedKeyBytes", Resources.UserImportBulkBlob);
			}

			var hProv = CryptoApiHelper.ProviderHandle;
			SafeKeyHandleImpl hKey;

			_providerParameters.KeyNumber = CryptoApiHelper.ImportCspBlob(importedKeyBytes, hProv, SafeKeyHandleImpl.InvalidHandle, out hKey);
			_providerHandle = hProv;
			_keyHandle = hKey;

			_isPublicKeyOnly = true;
		}

		private static bool IsPublicKeyBlob(byte[] importedKeyBytes)
		{
			if ((importedKeyBytes[0] != Constants.PUBLICKEYBLOB) || (importedKeyBytes.Length < 12))
			{
				return false;
			}

			var gostKeyMask = BitConverter.GetBytes(Constants.GR3410_1_MAGIC);

			return (importedKeyBytes[8] == gostKeyMask[0])
				   && (importedKeyBytes[9] == gostKeyMask[1])
				   && (importedKeyBytes[10] == gostKeyMask[2])
				   && (importedKeyBytes[11] == gostKeyMask[3]);
		}


		/// <summary>
		/// Вычисляет цифровую подпись.
		/// </summary>
		public override byte[] CreateSignature(byte[] hash)
		{
			return SignHash(hash);
		}

		/// <summary>
		/// Вычисляет цифровую подпись.
		/// </summary>
		[SecuritySafeCritical]
		public byte[] CreateSignature(byte[] data, object hashAlgorithm)
		{
			var hash = CreateHashAlgorithm(hashAlgorithm).ComputeHash(data);
			return SignHash(hash);
		}

		/// <summary>
		/// Вычисляет цифровую подпись.
		/// </summary>
		[SecuritySafeCritical]
		public byte[] CreateSignature(Stream data, object hashAlgorithm)
		{
			var hash = CreateHashAlgorithm(hashAlgorithm).ComputeHash(data);
			return SignHash(hash);
		}

		/// <summary>
		/// Вычисляет цифровую подпись.
		/// </summary>
		[SecuritySafeCritical]
		public byte[] CreateSignature(byte[] data, int dataOffset, int dataLength, object hashAlgorithm)
		{
			var hash = CreateHashAlgorithm(hashAlgorithm).ComputeHash(data, dataOffset, dataLength);
			return SignHash(hash);
		}

		[SecuritySafeCritical]
		private byte[] SignHash(byte[] hash)
		{
			if (hash == null)
			{
				throw ExceptionUtility.ArgumentNull("hash");
			}

			if (hash.Length != 32)
			{
				throw ExceptionUtility.ArgumentOutOfRange("hash", Resources.InvalidHashSize);
			}

			if (IsPublicKeyOnly)
			{
				throw ExceptionUtility.CryptographicException(Resources.NoPrivateKey);
			}

			GetKeyPair();

			if (!CspKeyContainerInfo.RandomlyGenerated)
			{
				var keyContainerPermission = new KeyContainerPermission(KeyContainerPermissionFlags.NoFlags);
				var keyContainerAccessEntry = new KeyContainerPermissionAccessEntry(_providerParameters, KeyContainerPermissionFlags.Sign);
				keyContainerPermission.AccessEntries.Add(keyContainerAccessEntry);
				keyContainerPermission.Demand();
			}

			return CryptoApiHelper.SignValue(_providerHandle, _providerParameters.KeyNumber, hash);
		}


		/// <summary>
		/// Проверяет цифровую подпись.
		/// </summary>
		public override bool VerifySignature(byte[] hash, byte[] signature)
		{
			return VerifyHash(hash, signature);
		}

		/// <summary>
		/// Проверяет цифровую подпись.
		/// </summary>
		[SecuritySafeCritical]
		public bool VerifySignature(byte[] buffer, object hashAlgorithm, byte[] signature)
		{
			var hash = CreateHashAlgorithm(hashAlgorithm).ComputeHash(buffer);
			return VerifyHash(hash, signature);
		}

		/// <summary>
		/// Проверяет цифровую подпись.
		/// </summary>
		[SecuritySafeCritical]
		public bool VerifySignature(Stream inputStream, object hashAlgorithm, byte[] signature)
		{
			var hash = CreateHashAlgorithm(hashAlgorithm).ComputeHash(inputStream);
			return VerifyHash(hash, signature);
		}

		/// <summary>
		/// Проверяет цифровую подпись.
		/// </summary>
		public bool VerifySignature(byte[] data, int dataOffset, int dataLength, object hashAlgorithm, byte[] signature)
		{
			var hash = CreateHashAlgorithm(hashAlgorithm).ComputeHash(data, dataOffset, dataLength);
			return VerifyHash(hash, signature);
		}

		[SecuritySafeCritical]
		private bool VerifyHash(byte[] hash, byte[] signature)
		{
			if (hash == null)
			{
				throw ExceptionUtility.ArgumentNull("hash");
			}

			if (signature == null)
			{
				throw ExceptionUtility.ArgumentNull("signature");
			}

			if (hash.Length != 32)
			{
				throw ExceptionUtility.ArgumentOutOfRange(Resources.InvalidHashSize);
			}

			GetKeyPair();

			return CryptoApiHelper.VerifySign(_providerHandle, _keyHandle, hash, signature);
		}


		/// <summary>
		/// Создает общий секретный ключ.
		/// </summary>
		/// <param name="keyParameters">Параметры открытого ключа, используемого для создания общего секретного ключа.</param>
		[SecuritySafeCritical]
		public override GostKeyExchangeAlgorithmBase CreateKeyExchange(GostKeyExchangeParameters keyParameters)
		{
			GetKeyPair();

			return new GostKeyExchangeAlgorithm(_providerHandle, _keyHandle, new GostKeyExchangeParameters(keyParameters));
		}


		/// <summary>
		/// Экспортирует (шифрует) параметры ключа, используемого для создания общего секретного ключа.
		/// </summary>
		/// <param name="includePrivateKey">Включить секретный ключ.</param>
		/// <exception cref="NotSupportedException"></exception>
		[SecuritySafeCritical]
		public override GostKeyExchangeParameters ExportParameters(bool includePrivateKey)
		{
			if (includePrivateKey)
			{
				throw ExceptionUtility.NotSupported(Resources.UserExportBulkKeyNotSupported);
			}

			GetKeyPair();

			return CryptoApiHelper.ExportPublicKey(_keyHandle);
		}

		/// <summary>
		/// Импортирует (дешифрует) параметры ключа, используемого для создания общего секретного ключа.
		/// </summary>
		/// <param name="keyParameters">Параметры ключа, используемого для создания общего секретного ключа.</param>
		/// <exception cref="NotSupportedException"></exception>
		[SecuritySafeCritical]
		public override void ImportParameters(GostKeyExchangeParameters keyParameters)
		{
			if (keyParameters.PrivateKey != null)
			{
				throw ExceptionUtility.NotSupported(Resources.UserImportBulkKeyNotSupported);
			}

			_keyHandle.TryDispose();

			_providerHandle = CryptoApiHelper.ProviderHandle;
			_keyHandle = CryptoApiHelper.ImportPublicKey(_providerHandle, new GostKeyExchangeParameters(keyParameters));

			_isPublicKeyOnly = true;
		}


		/// <summary>
		/// Установка пароля доступа к контейнеру.
		/// </summary>
		[SecuritySafeCritical]
		[SecurityPermission(SecurityAction.Assert, UnmanagedCode = true)]
		public void SetContainerPassword(SecureString password)
		{
			if (IsPublicKeyOnly)
			{
				throw ExceptionUtility.CryptographicException(Resources.NoPrivateKey);
			}

			GetKeyPair();
			SetSignatureKeyPassword(_providerHandle, password, _providerParameters.KeyNumber);
		}


		[SecuritySafeCritical]
		protected override void Dispose(bool disposing)
		{
			_keyHandle.TryDispose();

			if (!_isPublicKeyOnly)
			{
				_providerHandle.TryDispose();
			}

			base.Dispose(disposing);
		}


		// Helpers

		private static readonly object ObjToHashAlgorithmMethodSync = new object();

		private static volatile MethodInfo _objToHashAlgorithmMethod;

		private static HashAlgorithm CreateHashAlgorithm(object hashAlg)
		{
			if (hashAlg == null)
			{
				throw ExceptionUtility.ArgumentNull("hashAlg");
			}

			if (!GetHashAlgorithmOid(hashAlg).Equals(GostCryptoConfig.DefaultHashOid, StringComparison.OrdinalIgnoreCase))
			{
				throw ExceptionUtility.Argument("hashAlg", Resources.RequiredGost3411);
			}

			HashAlgorithm hashAlgorithm = null;

			if (_objToHashAlgorithmMethod == null)
			{
				lock (ObjToHashAlgorithmMethodSync)
				{
					if (_objToHashAlgorithmMethod == null)
					{
						var utilsType = Type.GetType("System.Security.Cryptography.Utils");

						if (utilsType != null)
						{
							_objToHashAlgorithmMethod = utilsType.GetMethod("ObjToHashAlgorithm", BindingFlags.Static | BindingFlags.NonPublic, null, new[] { typeof(object) }, null);
						}
					}
				}
			}

			if (_objToHashAlgorithmMethod != null)
			{
				try
				{
					hashAlgorithm = _objToHashAlgorithmMethod.Invoke(null, new[] { hashAlg }) as HashAlgorithm;
				}
				catch (TargetInvocationException exception)
				{
					if (exception.InnerException != null)
					{
						throw exception.InnerException;
					}

					throw;
				}
			}

			return hashAlgorithm;
		}

		private static string GetHashAlgorithmOid(object hashAlg)
		{
			string hashAlgOid = null;

			if (hashAlg is string)
			{
				hashAlgOid = GostCryptoConfig.MapNameToOid((string)hashAlg);

				if (string.IsNullOrEmpty(hashAlgOid))
				{
					hashAlgOid = (string)hashAlg;
				}
			}
			else if (hashAlg is HashAlgorithm)
			{
				hashAlgOid = GostCryptoConfig.MapNameToOid(hashAlg.GetType().ToString());
			}
			else if (hashAlg is Type)
			{
				hashAlgOid = GostCryptoConfig.MapNameToOid(hashAlg.ToString());
			}

			if (string.IsNullOrEmpty(hashAlgOid))
			{
				throw ExceptionUtility.Argument("hashAlg", Resources.InvalidHashAlgorithm);
			}

			return hashAlgOid;
		}

		[SecurityCritical]
		private void GetKeyPair()
		{
			if (_keyHandle == null)
			{
				lock (this)
				{
					if (_keyHandle == null)
					{
						SafeProvHandleImpl providerHandle;
						SafeKeyHandleImpl keyHandle;

						GetKeyPairValue(_providerParameters, _isRandomKeyContainer, out providerHandle, out keyHandle);

						_providerHandle = providerHandle;
						_keyHandle = keyHandle;

						_isPersistentKey = true;
					}
				}
			}
		}

		private static void GetKeyPairValue(CspParameters providerParams, bool randomKeyContainer, out SafeProvHandleImpl providerHandle, out SafeKeyHandleImpl keyHandle)
		{
			SafeProvHandleImpl resultProviderHandle = null;

			SafeKeyHandleImpl resultKeyHandle = null;

			try
			{
				resultProviderHandle = CreateProviderHandle(providerParams, randomKeyContainer);

				if (providerParams.ParentWindowHandle != IntPtr.Zero)
				{
					CryptoApiHelper.SetProviderParameter(resultProviderHandle, providerParams.KeyNumber, Constants.PP_CLIENT_HWND, providerParams.ParentWindowHandle);
				}
				else if (providerParams.KeyPassword != null)
				{
					SetSignatureKeyPassword(resultProviderHandle, providerParams.KeyPassword, providerParams.KeyNumber);
				}

				try
				{
					resultKeyHandle = CryptoApiHelper.GetUserKey(resultProviderHandle, providerParams.KeyNumber);
				}
				catch (Exception exception)
				{
					var errorCode = Marshal.GetHRForException(exception);

					if (errorCode != 0)
					{
						if (((providerParams.Flags & CspProviderFlags.UseExistingKey) != CspProviderFlags.NoFlags) || (errorCode != Constants.NTE_NO_KEY))
						{
							throw;
						}

						resultKeyHandle = CryptoApiHelper.GenerateKey(resultProviderHandle, providerParams.KeyNumber, providerParams.Flags);
					}
				}

				var keyAlgIdInverted = CryptoApiHelper.GetKeyParameter(resultKeyHandle, Constants.KP_ALGID);
				var keyAlgId = keyAlgIdInverted[0] | (keyAlgIdInverted[1] << 8) | (keyAlgIdInverted[2] << 16) | (keyAlgIdInverted[3] << 24);

				if ((keyAlgId != Constants.CALG_DH_EL_SF) && (keyAlgId != Constants.CALG_GR3410EL))
				{
					throw ExceptionUtility.NotSupported(Resources.KeyAlgorithmNotSupported);
				}
			}
			catch (Exception)
			{
				if (resultProviderHandle != null)
				{
					resultProviderHandle.Close();
				}

				if (resultKeyHandle != null)
				{
					resultKeyHandle.Close();
				}

				throw;
			}

			providerHandle = resultProviderHandle;
			keyHandle = resultKeyHandle;
		}

		private static SafeProvHandleImpl CreateProviderHandle(CspParameters providerParams, bool randomKeyContainer)
		{
			SafeProvHandleImpl propvoderHandle = null;

			var keyContainerPermission = new KeyContainerPermission(KeyContainerPermissionFlags.NoFlags);

			try
			{
				propvoderHandle = CryptoApiHelper.OpenProvider(providerParams);
			}
			catch (Exception exception)
			{
				var errorCode = Marshal.GetHRForException(exception);

				if (errorCode != 0)
				{
					if (((providerParams.Flags & CspProviderFlags.UseExistingKey) != CspProviderFlags.NoFlags)
						|| ((errorCode != Constants.NTE_KEYSET_NOT_DEF)
							&& (errorCode != Constants.NTE_BAD_KEYSET)
							&& (errorCode != Constants.SCARD_W_CANCELLED_BY_USER)))
					{
						throw ExceptionUtility.CryptographicException(errorCode);
					}

					if (!randomKeyContainer)
					{
						var containerAccessEntry = new KeyContainerPermissionAccessEntry(providerParams, KeyContainerPermissionFlags.Create);
						keyContainerPermission.AccessEntries.Add(containerAccessEntry);
						keyContainerPermission.Demand();
					}

					propvoderHandle = CryptoApiHelper.CreateProvider(providerParams);

					return propvoderHandle;
				}
			}

			if (!randomKeyContainer)
			{
				var containerAccessEntry = new KeyContainerPermissionAccessEntry(providerParams, KeyContainerPermissionFlags.Open);
				keyContainerPermission.AccessEntries.Add(containerAccessEntry);
				keyContainerPermission.Demand();
			}

			return propvoderHandle;
		}

		private static void SetSignatureKeyPassword(SafeProvHandleImpl hProv, SecureString keyPassword, int keyNumber)
		{
			if (keyPassword == null)
			{
				throw ExceptionUtility.ArgumentNull("keyPassword");
			}

			var keyPasswordData = Marshal.SecureStringToCoTaskMemAnsi(keyPassword);

			try
			{
				CryptoApiHelper.SetProviderParameter(hProv, keyNumber, Constants.PP_SIGNATURE_PIN, keyPasswordData);
			}
			finally
			{
				if (keyPasswordData != IntPtr.Zero)
				{
					Marshal.ZeroFreeCoTaskMemAnsi(keyPasswordData);
				}
			}
		}

		private static CspParameters CreateProviderParameters(CspParameters providerParameters, CspProviderFlags defaultFlags, out bool randomKeyContainer)
		{
			CspParameters parameters;

			if (providerParameters == null)
			{
				parameters = new CspParameters(GostCryptoConfig.ProviderType) { Flags = defaultFlags };
			}
			else
			{
				ValidateProviderParameters(providerParameters.Flags);

				parameters = new CspParameters(providerParameters.ProviderType, providerParameters.ProviderName, providerParameters.KeyContainerName) { Flags = providerParameters.Flags, KeyNumber = providerParameters.KeyNumber };
			}

			// Установка типа ключа
			if (parameters.KeyNumber == -1)
			{
				parameters.KeyNumber = (int)KeyNumber.Exchange;
			}
			else if (parameters.KeyNumber == Constants.CALG_GR3410EL)
			{
				parameters.KeyNumber = (int)KeyNumber.Signature;
			}
			else if (parameters.KeyNumber == Constants.CALG_DH_EL_SF)
			{
				parameters.KeyNumber = (int)KeyNumber.Exchange;
			}

			// Использовать автогенерированный контейнер
			randomKeyContainer = ((parameters.KeyContainerName == null) && ((parameters.Flags & CspProviderFlags.UseDefaultKeyContainer) == CspProviderFlags.NoFlags));

			if (randomKeyContainer)
			{
				parameters.KeyContainerName = Guid.NewGuid().ToString();
			}

			return parameters;
		}

		private static void ValidateProviderParameters(CspProviderFlags flags)
		{
			// Ели информацию о провайдере нужно взять из текущего ключа
			if ((flags & CspProviderFlags.UseExistingKey) != CspProviderFlags.NoFlags)
			{
				const CspProviderFlags notExpectedFlags = CspProviderFlags.UseUserProtectedKey
														  | CspProviderFlags.UseArchivableKey
														  | CspProviderFlags.UseNonExportableKey;

				if ((flags & notExpectedFlags) != CspProviderFlags.NoFlags)
				{
					throw ExceptionUtility.Argument("flags", Resources.InvalidCspProviderFlags);
				}
			}

			// Если пользователь должен сам выбрать ключ (например, в диалоге)
			if ((flags & CspProviderFlags.UseUserProtectedKey) != CspProviderFlags.NoFlags)
			{
				if (!Environment.UserInteractive)
				{
					throw ExceptionUtility.CryptographicException(Resources.UserInteractiveNotSupported);
				}

				new UIPermission(UIPermissionWindow.SafeTopLevelWindows).Demand();
			}
		}
	}
}