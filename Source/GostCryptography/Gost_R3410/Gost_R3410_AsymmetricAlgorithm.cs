using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;

using GostCryptography.Asn1.Gost.Gost_R3410;
using GostCryptography.Base;
using GostCryptography.Native;
using GostCryptography.Properties;
using GostCryptography.Reflection;

namespace GostCryptography.Gost_R3410
{
	/// <inheritdoc cref="Gost_R3410_AsymmetricAlgorithmBase{TKeyParams,TKeyAlgorithm}" />
	public abstract class Gost_R3410_AsymmetricAlgorithm<TKeyParams, TKeyAlgorithm> : Gost_R3410_AsymmetricAlgorithmBase<TKeyParams, TKeyAlgorithm>, ICspAsymmetricAlgorithm, ISafeHandleProvider<SafeProvHandleImpl>, ISafeHandleProvider<SafeKeyHandleImpl>
		where TKeyParams : Gost_R3410_KeyExchangeParams
		where TKeyAlgorithm : Gost_R3410_KeyExchangeAlgorithm
	{
		/// <inheritdoc />
		[SecuritySafeCritical]
		protected Gost_R3410_AsymmetricAlgorithm(ProviderType providerType, int keySize) : base(providerType, keySize)
		{
			_providerParameters = CreateDefaultProviderParameters();
			InitKeyContainer(_providerParameters, out _isRandomKeyContainer);
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerParameters">Параметры криптографического провайдера.</param>
		/// <param name="keySize">Размер ключа в битах.</param>
		[SecuritySafeCritical]
		protected Gost_R3410_AsymmetricAlgorithm(CspParameters providerParameters, int keySize) : base((ProviderType)providerParameters.ProviderType, keySize)
		{
			_providerParameters = CopyExistingProviderParameters(providerParameters);
			InitKeyContainer(_providerParameters, out _isRandomKeyContainer);
		}


		private readonly CspParameters _providerParameters;
		private readonly bool _isRandomKeyContainer;
		private bool _isPersistentKey;
		private bool _isPublicKeyOnly;

		[SecurityCritical]
		private SafeProvHandleImpl _providerHandle;
		[SecurityCritical]
		private volatile SafeKeyHandleImpl _keyHandle;


		/// <inheritdoc />
		SafeProvHandleImpl ISafeHandleProvider<SafeProvHandleImpl>.SafeHandle
		{
			[SecurityCritical]
			get
			{
				GetKeyPair();

				return _providerHandle;
			}
		}

		/// <inheritdoc />
		SafeKeyHandleImpl ISafeHandleProvider<SafeKeyHandleImpl>.SafeHandle
		{
			[SecurityCritical]
			get
			{
				GetKeyPair();

				return _keyHandle;
			}
		}

		/// <inheritdoc />
		public override int KeySize
		{
			[SecuritySafeCritical]
			get
			{
				GetKeyPair();

				return base.KeySize;
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

		/// <inheritdoc />
		public CspKeyContainerInfo CspKeyContainerInfo
		{
			[SecuritySafeCritical]
			get
			{
				GetKeyPair();

				return CspKeyContainerInfoHelper.CreateCspKeyContainerInfo(_providerParameters, _isRandomKeyContainer);
			}
		}


		/// <inheritdoc />
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

		/// <inheritdoc />
		[SecuritySafeCritical]
		public void ImportCspBlob(byte[] importedKeyBytes)
		{
			if (importedKeyBytes == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(importedKeyBytes));
			}

			if (!IsPublicKeyBlob(importedKeyBytes))
			{
				throw ExceptionUtility.Argument(nameof(importedKeyBytes), Resources.UserImportBulkBlob);
			}

			var hProv = CryptoApiHelper.GetProviderHandle(ProviderType);

			_providerParameters.KeyNumber = CryptoApiHelper.ImportCspBlob(importedKeyBytes, hProv, SafeKeyHandleImpl.InvalidHandle, out var hKey);
			_providerHandle = hProv;
			_keyHandle = hKey;

			_isPublicKeyOnly = true;
		}

		[SecuritySafeCritical]
		public void ImportCspBlob(byte[] encodedParameters, byte[] encodedKeyValue)
		{
			var keyParams = CreateKeyExchangeParams();
			keyParams.DecodeParameters(encodedParameters);
			keyParams.DecodePublicKey(encodedKeyValue);

			var keyBytes = CryptoApiHelper.EncodePublicBlob(keyParams, KeySizeValue, SignatureAlgId);

			ImportCspBlob(keyBytes);
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


		/// <inheritdoc />
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
			var hash = CryptographyUtils.ObjToHashAlgorithm(hashAlgorithm).ComputeHash(data);
			return SignHash(hash);
		}

		/// <summary>
		/// Вычисляет цифровую подпись.
		/// </summary>
		[SecuritySafeCritical]
		public byte[] CreateSignature(Stream data, object hashAlgorithm)
		{
			var hash = CryptographyUtils.ObjToHashAlgorithm(hashAlgorithm).ComputeHash(data);
			return SignHash(hash);
		}

		/// <summary>
		/// Вычисляет цифровую подпись.
		/// </summary>
		[SecuritySafeCritical]
		public byte[] CreateSignature(byte[] data, int dataOffset, int dataLength, object hashAlgorithm)
		{
			var hash = CryptographyUtils.ObjToHashAlgorithm(hashAlgorithm).ComputeHash(data, dataOffset, dataLength);
			return SignHash(hash);
		}

		[SecuritySafeCritical]
		private byte[] SignHash(byte[] hash)
		{
			ValidateHashParameter(hash);

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

			using (var hashAlgorithm = CreateHashAlgorithm())
			{
				var hashHandleProvider = (ISafeHandleProvider<SafeHashHandleImpl>)hashAlgorithm;
				return CryptoApiHelper.SignValue(_providerHandle, hashHandleProvider.SafeHandle, _providerParameters.KeyNumber, hash);
			}
		}


		/// <inheritdoc />
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
			var hash = CryptographyUtils.ObjToHashAlgorithm(hashAlgorithm).ComputeHash(buffer);
			return VerifyHash(hash, signature);
		}

		/// <summary>
		/// Проверяет цифровую подпись.
		/// </summary>
		[SecuritySafeCritical]
		public bool VerifySignature(Stream inputStream, object hashAlgorithm, byte[] signature)
		{
			var hash = CryptographyUtils.ObjToHashAlgorithm(hashAlgorithm).ComputeHash(inputStream);
			return VerifyHash(hash, signature);
		}

		/// <summary>
		/// Проверяет цифровую подпись.
		/// </summary>
		public bool VerifySignature(byte[] data, int dataOffset, int dataLength, object hashAlgorithm, byte[] signature)
		{
			var hash = CryptographyUtils.ObjToHashAlgorithm(hashAlgorithm).ComputeHash(data, dataOffset, dataLength);
			return VerifyHash(hash, signature);
		}

		[SecuritySafeCritical]
		private bool VerifyHash(byte[] hash, byte[] signature)
		{
			ValidateHashParameter(hash);

			if (signature == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(signature));
			}

			GetKeyPair();

			using (var hashAlgorithm = CreateHashAlgorithm())
			{
				var hashHandleProvider = (ISafeHandleProvider<SafeHashHandleImpl>)hashAlgorithm;
				return CryptoApiHelper.VerifySign(_providerHandle, hashHandleProvider.SafeHandle, _keyHandle, hash, signature);
			}
		}


		/// <summary>
		/// Проверяет корректность хэша.
		/// </summary>
		protected abstract void ValidateHashParameter(byte[] hash);


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override TKeyAlgorithm CreateKeyExchange(TKeyParams keyParameters)
		{
			GetKeyPair();

			return CreateKeyExchangeAlgorithm(ProviderType, _providerHandle, _keyHandle, (TKeyParams)keyParameters.Clone());
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override TKeyParams ExportParameters(bool includePrivateKey)
		{
			if (includePrivateKey)
			{
				throw ExceptionUtility.NotSupported(Resources.UserExportBulkKeyNotSupported);
			}

			GetKeyPair();

			return CryptoApiHelper.ExportPublicKey(_keyHandle, CreateKeyExchangeParams(), KeySizeValue);
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public override void ImportParameters(TKeyParams keyParameters)
		{
			if (keyParameters.PrivateKey != null)
			{
				throw ExceptionUtility.NotSupported(Resources.UserImportBulkKeyNotSupported);
			}

			_keyHandle.TryDispose();

			var hProv = CryptoApiHelper.GetProviderHandle(ProviderType);

			var importedKeyBytes = CryptoApiHelper.EncodePublicBlob(keyParameters.Clone(), KeySizeValue, SignatureAlgId);

			_providerParameters.KeyNumber = CryptoApiHelper.ImportCspBlob(importedKeyBytes, hProv, SafeKeyHandleImpl.InvalidHandle, out var keyHandle);
			_providerHandle = hProv;
			_keyHandle = keyHandle;

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


		/// <inheritdoc />
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

		[SecurityCritical]
		private void GetKeyPair()
		{
			if (_keyHandle == null)
			{
				lock (this)
				{
					if (_keyHandle == null)
					{
						GetKeyPairValue(_providerParameters, _isRandomKeyContainer, out var providerHandle, out var keyHandle);

						_providerHandle = providerHandle;
						_keyHandle = keyHandle;

						_isPersistentKey = true;
					}
				}
			}
		}


		[SecurityCritical]
		private void GetKeyPairValue(CspParameters providerParams, bool randomKeyContainer, out SafeProvHandleImpl providerHandle, out SafeKeyHandleImpl keyHandle)
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

				if ((keyAlgId != ExchangeAlgId) && (keyAlgId != SignatureAlgId))
				{
					throw ExceptionUtility.NotSupported(Resources.KeyAlgorithmNotSupported);
				}
			}
			catch (Exception)
			{
				resultProviderHandle?.Close();
				resultKeyHandle?.Close();
				throw;
			}

			providerHandle = resultProviderHandle;
			keyHandle = resultKeyHandle;
		}

		[SecurityCritical]
		private static SafeProvHandleImpl CreateProviderHandle(CspParameters providerParams, bool randomKeyContainer)
		{
			SafeProvHandleImpl providerHandle = null;

			var keyContainerPermission = new KeyContainerPermission(KeyContainerPermissionFlags.NoFlags);

			try
			{
				providerHandle = CryptoApiHelper.OpenProvider(providerParams);
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

					providerHandle = CryptoApiHelper.CreateProvider(providerParams);

					return providerHandle;
				}
			}

			if (!randomKeyContainer)
			{
				var containerAccessEntry = new KeyContainerPermissionAccessEntry(providerParams, KeyContainerPermissionFlags.Open);
				keyContainerPermission.AccessEntries.Add(containerAccessEntry);
				keyContainerPermission.Demand();
			}

			return providerHandle;
		}

		[SecuritySafeCritical]
		private static void SetSignatureKeyPassword(SafeProvHandleImpl hProv, SecureString keyPassword, int keyNumber)
		{
			if (keyPassword == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyPassword));
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


		private CspParameters CreateDefaultProviderParameters(CspProviderFlags defaultFlags = CspProviderFlags.UseMachineKeyStore)
		{
			return new CspParameters(ProviderType.ToInt())
			{
				Flags = defaultFlags
			};
		}

		private CspParameters CopyExistingProviderParameters(CspParameters providerParameters)
		{
			ValidateProviderParameters(providerParameters.Flags);

			return new CspParameters(providerParameters.ProviderType, providerParameters.ProviderName, providerParameters.KeyContainerName)
			{
				Flags = providerParameters.Flags,
				KeyNumber = providerParameters.KeyNumber
			};
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
					throw ExceptionUtility.Argument(nameof(flags), Resources.InvalidCspProviderFlags);
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


		[SecurityCritical]
		private void InitKeyContainer(CspParameters providerParameters, out bool randomKeyContainer)
		{
			// Установка типа ключа
			if (providerParameters.KeyNumber == -1)
			{
				providerParameters.KeyNumber = (int)KeyNumber.Exchange;
			}
			else if (providerParameters.KeyNumber == SignatureAlgId)
			{
				providerParameters.KeyNumber = (int)KeyNumber.Signature;
			}
			else if (providerParameters.KeyNumber == ExchangeAlgId)
			{
				providerParameters.KeyNumber = (int)KeyNumber.Exchange;
			}

			// Использовать автогенерированный контейнер
			randomKeyContainer = ((providerParameters.KeyContainerName == null) && ((providerParameters.Flags & CspProviderFlags.UseDefaultKeyContainer) == CspProviderFlags.NoFlags));

			if (randomKeyContainer)
			{
				providerParameters.KeyContainerName = Guid.NewGuid().ToString();
			}
			else
			{
				GetKeyPair();
			}
		}
	}
}