using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

using GostCryptography.Asn1.Gost.Gost_28147_89;
using GostCryptography.Asn1.Gost.Gost_R3410;
using GostCryptography.Base;
using GostCryptography.Properties;

namespace GostCryptography.Native
{
	/// <summary>
	/// Вспомогательные методы для работы с Microsoft CryptoAPI.
	/// </summary>
	[SecurityCritical]
	public static class CryptoApiHelper
	{
		/// <summary>
		/// Возвращает <see langword="true"/>, если заданный провайдер установлен.
		/// </summary>
		[SecurityCritical]
		public static bool IsInstalled(ProviderType providerType)
		{
			try
			{
				var providerHandle = GetProviderHandle(providerType);
				return !providerHandle.IsInvalid;
			}
			catch
			{
				return false;
			}
		}

		/// <summary>
		/// Возвращает доступный провайдер для ключей ГОСТ Р 34.10-2001.
		/// </summary>
		/// <exception cref="CryptographicException">Провайдер не установлен.</exception>
		[SecuritySafeCritical]
		public static ProviderType GetAvailableProviderType_2001()
		{
			if (IsInstalled(ProviderType.VipNet))
			{
				return ProviderType.VipNet;
			}

			if (IsInstalled(ProviderType.CryptoPro))
			{
				return ProviderType.CryptoPro;
			}

			throw ExceptionUtility.CryptographicException(Resources.Provider_2001_IsNotInstalled);
		}

		/// <summary>
		/// Возвращает доступный провайдер для ключей ГОСТ Р 34.10-2012/512.
		/// </summary>
		/// <exception cref="CryptographicException">Провайдер не установлен.</exception>
		[SecuritySafeCritical]
		public static ProviderType GetAvailableProviderType_2012_512()
		{
			if (IsInstalled(ProviderType.VipNet_2012_512))
			{
				return ProviderType.VipNet_2012_512;
			}

			if (IsInstalled(ProviderType.CryptoPro_2012_512))
			{
				return ProviderType.CryptoPro_2012_512;
			}

			throw ExceptionUtility.CryptographicException(Resources.Provider_2012_512_IsNotInstalled);
		}

		/// <summary>
		/// Возвращает доступный провайдер для ключей ГОСТ Р 34.10-2012/1024.
		/// </summary>
		/// <exception cref="CryptographicException">Провайдер не установлен.</exception>
		[SecuritySafeCritical]
		public static ProviderType GetAvailableProviderType_2012_1024()
		{
			if (IsInstalled(ProviderType.VipNet_2012_1024))
			{
				return ProviderType.VipNet_2012_1024;
			}

			if (IsInstalled(ProviderType.CryptoPro_2012_1024))
			{
				return ProviderType.CryptoPro_2012_1024;
			}

			throw ExceptionUtility.CryptographicException(Resources.Provider_2012_1024_IsNotInstalled);
		}


		#region Общие объекты

		private static readonly object ProviderHandleSync = new object();
		private static volatile Dictionary<ProviderType, SafeProvHandleImpl> _providerHandles = new Dictionary<ProviderType, SafeProvHandleImpl>();

		public static SafeProvHandleImpl GetProviderHandle(ProviderType providerType)
		{
			if (!_providerHandles.ContainsKey(providerType))
			{
				lock (ProviderHandleSync)
				{
					if (!_providerHandles.ContainsKey(providerType))
					{
						var providerParams = new CspParameters(providerType.ToInt());
						var providerHandle = AcquireProvider(providerParams);

						Thread.MemoryBarrier();

						_providerHandles.Add(providerType, providerHandle);
					}
				}
			}

			return _providerHandles[providerType];
		}


		private static readonly object RandomNumberGeneratorSync = new object();
		private static volatile Dictionary<ProviderType, RNGCryptoServiceProvider> _randomNumberGenerators = new Dictionary<ProviderType, RNGCryptoServiceProvider>();

		public static RNGCryptoServiceProvider GetRandomNumberGenerator(ProviderType providerType)
		{
			if (!_randomNumberGenerators.ContainsKey(providerType))
			{
				lock (RandomNumberGeneratorSync)
				{
					if (!_randomNumberGenerators.ContainsKey(providerType))
					{
						var providerParams = new CspParameters(providerType.ToInt());
						var randomNumberGenerator = new RNGCryptoServiceProvider(providerParams);

						Thread.MemoryBarrier();

						_randomNumberGenerators.Add(providerType, randomNumberGenerator);
					}
				}
			}

			return _randomNumberGenerators[providerType];
		}

		#endregion


		#region Для работы с криптографическим провайдером

		public static SafeProvHandleImpl AcquireProvider(CspParameters providerParameters)
		{
			var providerHandle = SafeProvHandleImpl.InvalidHandle;

			var dwFlags = Constants.CRYPT_VERIFYCONTEXT;

			if ((providerParameters.Flags & CspProviderFlags.UseMachineKeyStore) != CspProviderFlags.NoFlags)
			{
				dwFlags |= Constants.CRYPT_MACHINE_KEYSET;
			}

			if (!CryptoApi.CryptAcquireContext(ref providerHandle, providerParameters.KeyContainerName, providerParameters.ProviderName, (uint)providerParameters.ProviderType, dwFlags))
			{
				throw CreateWin32Error();
			}

			return providerHandle;
		}

		public static SafeProvHandleImpl OpenProvider(CspParameters providerParameters)
		{
			var providerHandle = SafeProvHandleImpl.InvalidHandle;
			var dwFlags = MapCspProviderFlags(providerParameters.Flags);

			if (!CryptoApi.CryptAcquireContext(ref providerHandle, providerParameters.KeyContainerName, providerParameters.ProviderName, (uint)providerParameters.ProviderType, dwFlags))
			{
				throw CreateWin32Error();
			}

			return providerHandle;
		}

		public static SafeProvHandleImpl CreateProvider(CspParameters providerParameters)
		{
			var providerHandle = SafeProvHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptAcquireContext(ref providerHandle, providerParameters.KeyContainerName, providerParameters.ProviderName, (uint)providerParameters.ProviderType, Constants.CRYPT_NEWKEYSET))
			{
				throw CreateWin32Error();
			}

			return providerHandle;
		}

		private static uint MapCspProviderFlags(CspProviderFlags flags)
		{
			uint dwFlags = 0;

			if ((flags & CspProviderFlags.UseMachineKeyStore) != CspProviderFlags.NoFlags)
			{
				dwFlags |= Constants.CRYPT_MACHINE_KEYSET;
			}

			if ((flags & CspProviderFlags.NoPrompt) != CspProviderFlags.NoFlags)
			{
				dwFlags |= Constants.CRYPT_PREGEN;
			}

			return dwFlags;
		}

		public static void SetProviderParameter(SafeProvHandleImpl providerHandle, int keyNumber, uint keyParamId, IntPtr keyParamValue)
		{
			if ((keyParamId == Constants.PP_KEYEXCHANGE_PIN) || (keyParamId == Constants.PP_SIGNATURE_PIN))
			{
				if (keyNumber == Constants.AT_KEYEXCHANGE)
				{
					keyParamId = Constants.PP_KEYEXCHANGE_PIN;
				}
				else if (keyNumber == Constants.AT_SIGNATURE)
				{
					keyParamId = Constants.PP_SIGNATURE_PIN;
				}
				else
				{
					throw ExceptionUtility.NotSupported(Resources.KeyAlgorithmNotSupported);
				}
			}

			if (!CryptoApi.CryptSetProvParam(providerHandle, keyParamId, keyParamValue, 0))
			{
				throw CreateWin32Error();
			}
		}

		public static ProviderType GetProviderType(SafeProvHandleImpl providerHandle)
		{
			uint providerTypeLen = sizeof(uint);
			byte[] dwData = new byte[sizeof(uint)];

			if (!CryptoApi.CryptGetProvParam(providerHandle, Constants.PP_PROVTYPE, dwData, ref providerTypeLen, 0))
			{
				throw CreateWin32Error();
			}

			var providerType = BitConverter.ToUInt32(dwData, 0);

			return (ProviderType)providerType;
		}

		#endregion


		#region Для работы с функцией хэширования криптографического провайдера

		public static SafeHashHandleImpl CreateHash_3411_94(SafeProvHandleImpl providerHandle)
		{
			return CreateHash_3411(providerHandle, Constants.CALG_GR3411);
		}

		public static SafeHashHandleImpl CreateHash_3411_2012_256(SafeProvHandleImpl providerHandle)
		{
			return CreateHash_3411(providerHandle, Constants.CALG_GR3411_2012_256);
		}

		public static SafeHashHandleImpl CreateHash_3411_2012_512(SafeProvHandleImpl providerHandle)
		{
			return CreateHash_3411(providerHandle, Constants.CALG_GR3411_2012_512);
		}

		private static SafeHashHandleImpl CreateHash_3411(SafeProvHandleImpl providerHandle, int hashAlgId)
		{
			var hashHandle = SafeHashHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptCreateHash(providerHandle, (uint)hashAlgId, SafeKeyHandleImpl.InvalidHandle, 0, ref hashHandle))
			{
				throw CreateWin32Error();
			}

			return hashHandle;
		}

		public static SafeHashHandleImpl CreateHashImit(SafeProvHandleImpl providerHandle, SafeKeyHandleImpl symKeyHandle)
		{
			var hashImitHandle = SafeHashHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptCreateHash(providerHandle, Constants.CALG_G28147_IMIT, symKeyHandle, 0, ref hashImitHandle))
			{
				throw CreateWin32Error();
			}

			return hashImitHandle;
		}

		public static SafeHashHandleImpl CreateHashHMAC_94(ProviderType providerType, SafeProvHandleImpl providerHandle, SafeKeyHandleImpl symKeyHandle)
		{
			var hmacAlgId = providerType.IsVipNet() ? Constants.CALG_GR3411 : Constants.CALG_GR3411_HMAC;
			return CreateHashHMAC(providerHandle, symKeyHandle, hmacAlgId);
		}

		public static SafeHashHandleImpl CreateHashHMAC_2012_256(ProviderType providerType, SafeProvHandleImpl providerHandle, SafeKeyHandleImpl symKeyHandle)
		{
			var hmacAlgId = providerType.IsVipNet() ? Constants.CALG_GR3411_2012_256 : Constants.CALG_GR3411_2012_256_HMAC;
			return CreateHashHMAC(providerHandle, symKeyHandle, hmacAlgId);
		}

		public static SafeHashHandleImpl CreateHashHMAC_2012_512(ProviderType providerType, SafeProvHandleImpl providerHandle, SafeKeyHandleImpl symKeyHandle)
		{
			var hmacAlgId = providerType.IsVipNet() ? Constants.CALG_GR3411_2012_512 : Constants.CALG_GR3411_2012_512_HMAC;
			return CreateHashHMAC(providerHandle, symKeyHandle, hmacAlgId);
		}

		private static SafeHashHandleImpl CreateHashHMAC(SafeProvHandleImpl providerHandle, SafeKeyHandleImpl symKeyHandle, int hmacAlgId)
		{
			var hashHmacHandle = SafeHashHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptCreateHash(providerHandle, (uint)hmacAlgId, symKeyHandle, 0, ref hashHmacHandle))
			{
				var errorCode = Marshal.GetLastWin32Error();

				if (errorCode == Constants.NTE_BAD_ALGID)
				{
					throw ExceptionUtility.CryptographicException(Resources.AlgorithmNotAvailable);
				}

				throw ExceptionUtility.CryptographicException(errorCode);
			}

			return hashHmacHandle;
		}

		public static unsafe void HashData(SafeHashHandleImpl hashHandle, byte[] data, int dataOffset, int dataLength)
		{
			if (data == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(data));
			}

			if (dataOffset < 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(dataOffset));
			}

			if (dataLength < 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(dataLength));
			}

			if (data.Length < dataOffset + dataLength)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(dataLength));
			}

			if (dataLength > 0)
			{
				fixed (byte* dataRef = data)
				{
					var dataOffsetRef = dataRef + dataOffset;

					if (!CryptoApi.CryptHashData(hashHandle, dataOffsetRef, (uint)dataLength, 0))
					{
						throw CreateWin32Error();
					}
				}
			}
		}

		public static byte[] EndHashData(SafeHashHandleImpl hashHandle)
		{
			uint dataLength = 0;

			if (!CryptoApi.CryptGetHashParam(hashHandle, Constants.HP_HASHVAL, null, ref dataLength, 0))
			{
				throw CreateWin32Error();
			}

			var data = new byte[dataLength];

			if (!CryptoApi.CryptGetHashParam(hashHandle, Constants.HP_HASHVAL, data, ref dataLength, 0))
			{
				throw CreateWin32Error();
			}

			return data;
		}

		public static void HashKeyExchange(SafeHashHandleImpl hashHandle, SafeKeyHandleImpl keyExchangeHandle)
		{
			if (!CryptoApi.CryptHashSessionKey(hashHandle, keyExchangeHandle, 0))
			{
				throw CreateWin32Error();
			}
		}

		#endregion


		#region Для работы с функцией шифрования криптографического провайдера

		public static int EncryptData(ProviderType providerType, SafeKeyHandleImpl symKeyHandle, byte[] data, int dataOffset, int dataLength, ref byte[] encryptedData, int encryptedDataOffset, PaddingMode paddingMode, bool isDone, bool isStream)
		{
			if (dataOffset < 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(dataOffset));
			}

			if (dataLength < 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(dataLength));
			}

			if (dataOffset > data.Length)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(dataOffset), Resources.InvalidDataOffset);
			}

			var length = dataLength;

			if (isDone)
			{
				length += 8;
			}

			// Выровненные данные
			var dataAlignLength = (uint)dataLength;
			var dataAlignArray = new byte[length];
			Array.Clear(dataAlignArray, 0, length);
			Array.Copy(data, dataOffset, dataAlignArray, 0, dataLength);

			if (isDone)
			{
				var dataPadding = dataLength & 7;
				var dataPaddingSize = (byte)(8 - dataPadding);

				// Добпаление дополнения данных в зависимости от настроек
				switch (paddingMode)
				{
					case PaddingMode.None:
						if ((dataPadding != 0) && !isStream)
						{
							throw ExceptionUtility.CryptographicException(Resources.EncryptInvalidDataSize);
						}

						break;
					case PaddingMode.Zeros:
						if (dataPadding != 0)
						{
							dataAlignLength += dataPaddingSize;

							// Дополнение заполняется нулевыми байтами
						}

						break;
					case PaddingMode.PKCS7:
						{
							dataAlignLength += dataPaddingSize;

							var paddingIndex = dataLength;

							// Дополнение заполняется байтами, в каждый из которых записывается размер дополнения
							while (paddingIndex < dataAlignLength)
							{
								dataAlignArray[paddingIndex++] = dataPaddingSize;
							}
						}
						break;
					case PaddingMode.ANSIX923:
						{
							dataAlignLength += dataPaddingSize;

							// Дополнение заполняется нулевыми, кроме последнего - в него записывается размер дополнения
							dataAlignArray[(int)((IntPtr)(dataAlignLength - 1))] = dataPaddingSize;
						}
						break;
					case PaddingMode.ISO10126:
						{
							dataAlignLength += dataPaddingSize;

							// Дополнение заполняется случайными байтами, кроме последнего - в него записывается размер дополнения
							var randomPadding = new byte[dataPaddingSize - 1];
							GetRandomNumberGenerator(providerType).GetBytes(randomPadding);
							randomPadding.CopyTo(dataAlignArray, dataLength);
							dataAlignArray[(int)((IntPtr)(dataAlignLength - 1))] = dataPaddingSize;
						}
						break;
					default:
						throw ExceptionUtility.Argument(nameof(paddingMode), Resources.InvalidPaddingMode);
				}
			}

			// Шифрование данных
			if (!CryptoApi.CryptEncrypt(symKeyHandle, SafeHashHandleImpl.InvalidHandle, false, 0, dataAlignArray, ref dataAlignLength, (uint)length))
			{
				throw CreateWin32Error();
			}

			// Копирование результата шифрования данных

			if (encryptedData == null)
			{
				encryptedData = new byte[dataAlignLength];

				Array.Copy(dataAlignArray, 0L, encryptedData, 0L, dataAlignLength);
			}
			else
			{
				if (encryptedDataOffset < 0)
				{
					throw ExceptionUtility.ArgumentOutOfRange(nameof(encryptedDataOffset));
				}

				if ((encryptedData.Length < dataAlignLength) || ((encryptedData.Length - dataAlignLength) < encryptedDataOffset))
				{
					throw ExceptionUtility.ArgumentOutOfRange(nameof(encryptedDataOffset), Resources.InvalidDataOffset);
				}

				Array.Copy(dataAlignArray, 0L, encryptedData, encryptedDataOffset, dataAlignLength);
			}

			return (int)dataAlignLength;
		}

		public static int DecryptData(SafeKeyHandleImpl symKeyHandle, byte[] data, int dataOffset, int dataLength, ref byte[] decryptedData, int decryptedDataOffset, PaddingMode paddingMode, bool isDone)
		{
			if (dataOffset < 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(dataOffset));
			}

			if (dataLength < 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(dataLength));
			}

			if ((dataOffset > data.Length) || ((dataOffset + dataLength) > data.Length))
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(dataOffset), Resources.InvalidDataOffset);
			}

			// Выровненные данные
			var dataAlignLength = (uint)dataLength;
			var dataAlign = new byte[dataAlignLength];
			Array.Copy(data, dataOffset, dataAlign, 0L, dataAlignLength);

			// Расшифровка данных
			if (!CryptoApi.CryptDecrypt(symKeyHandle, SafeHashHandleImpl.InvalidHandle, false, 0, dataAlign, ref dataAlignLength))
			{
				throw CreateWin32Error();
			}

			var length = (int)dataAlignLength;

			if (isDone)
			{
				byte dataPaddingSize = 0;

				// Удаление дополнения данных в зависимости от настроек
				if (((paddingMode == PaddingMode.PKCS7) || (paddingMode == PaddingMode.ANSIX923)) || (paddingMode == PaddingMode.ISO10126))
				{
					if (dataAlignLength < 8)
					{
						throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
					}

					// Размер дополнения находится в последнем байте
					dataPaddingSize = dataAlign[(int)((IntPtr)(dataAlignLength - 1))];

					if (dataPaddingSize > 8)
					{
						throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
					}

					// Проверка корректности дополнения данных
					if (paddingMode == PaddingMode.PKCS7)
					{
						for (var paddingIndex = dataAlignLength - dataPaddingSize; paddingIndex < (dataAlignLength - 1); paddingIndex++)
						{
							if (dataAlign[paddingIndex] != dataPaddingSize)
							{
								throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
							}
						}
					}
					else if (paddingMode == PaddingMode.ANSIX923)
					{
						for (var paddingIndex = dataAlignLength - dataPaddingSize; paddingIndex < (dataAlignLength - 1); paddingIndex++)
						{
							if (dataAlign[paddingIndex] != 0)
							{
								throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
							}
						}
					}
				}
				else if ((paddingMode != PaddingMode.None) && (paddingMode != PaddingMode.Zeros))
				{
					throw ExceptionUtility.Argument(nameof(paddingMode), Resources.InvalidPaddingMode);
				}

				length -= dataPaddingSize;
			}

			if (decryptedData == null)
			{
				decryptedData = new byte[length];

				Array.Copy(dataAlign, 0, decryptedData, 0, length);
			}
			else
			{
				if (decryptedDataOffset < 0)
				{
					throw ExceptionUtility.ArgumentOutOfRange(nameof(decryptedDataOffset));
				}

				if ((decryptedData.Length < length) || ((decryptedData.Length - length) < decryptedDataOffset))
				{
					throw ExceptionUtility.ArgumentOutOfRange(nameof(decryptedData), Resources.InvalidDataOffset);
				}

				Array.Copy(dataAlign, 0, decryptedData, decryptedDataOffset, length);
			}

			return length;
		}

		public static void EndEncrypt(ProviderType providerType, SafeKeyHandleImpl symKeyHandle)
		{
			uint dataLength = 0;
			var data = new byte[32];
			var success = CryptoApi.CryptEncrypt(symKeyHandle, SafeHashHandleImpl.InvalidHandle, true, 0, data, ref dataLength, (uint)data.Length);

			if (!success)
			{
				throw CreateWin32Error();
			}
		}

		public static void EndDecrypt(ProviderType providerType, SafeKeyHandleImpl symKeyHandle)
		{
			uint dataLength = 0;
			var data = new byte[0];
			var success = CryptoApi.CryptDecrypt(symKeyHandle, SafeHashHandleImpl.InvalidHandle, true, 0, data, ref dataLength) || providerType.IsVipNet();

			if (!success)
			{
				throw CreateWin32Error();
			}
		}

		#endregion


		#region Для работы с ключами криптографического провайдера

		public static SafeKeyHandleImpl GenerateKey(SafeProvHandleImpl providerHandle, int algId, CspProviderFlags flags)
		{
			var keyHandle = SafeKeyHandleImpl.InvalidHandle;
			var dwFlags = MapCspKeyFlags(flags);

			if (!CryptoApi.CryptGenKey(providerHandle, (uint)algId, dwFlags, ref keyHandle))
			{
				throw CreateWin32Error();
			}

			return keyHandle;
		}

		public static SafeKeyHandleImpl GenerateDhEphemeralKey(ProviderType providerType, SafeProvHandleImpl providerHandle, int algId, string digestParamSet, string publicKeyParamSet)
		{
			var keyHandle = SafeKeyHandleImpl.InvalidHandle;
			var dwFlags = MapCspKeyFlags(CspProviderFlags.NoFlags) | Constants.CRYPT_PREGEN;

			if (!CryptoApi.CryptGenKey(providerHandle, (uint)algId, dwFlags, ref keyHandle))
			{
				throw CreateWin32Error();
			}

			if (!providerType.IsVipNet())
			{
				SetKeyParameterString(keyHandle, Constants.KP_HASHOID, digestParamSet);
			}

			SetKeyParameterString(keyHandle, Constants.KP_DHOID, publicKeyParamSet);
			SetKeyParameter(keyHandle, Constants.KP_X, null);

			return keyHandle;
		}

		private static uint MapCspKeyFlags(CspProviderFlags flags)
		{
			uint dwFlags = 0;

			if ((flags & CspProviderFlags.UseNonExportableKey) == CspProviderFlags.NoFlags)
			{
				dwFlags |= Constants.CRYPT_EXPORTABLE;
			}

			if ((flags & CspProviderFlags.UseArchivableKey) != CspProviderFlags.NoFlags)
			{
				dwFlags |= Constants.CRYPT_ARCHIVABLE;
			}

			if ((flags & CspProviderFlags.UseUserProtectedKey) != CspProviderFlags.NoFlags)
			{
				dwFlags |= Constants.CRYPT_USER_PROTECTED;
			}

			return dwFlags;
		}

		public static SafeKeyHandleImpl GetUserKey(SafeProvHandleImpl providerHandle, int keyNumber)
		{
			var keyHandle = SafeKeyHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptGetUserKey(providerHandle, (uint)keyNumber, ref keyHandle))
			{
				throw CreateWin32Error();
			}

			return keyHandle;
		}

		public static SafeKeyHandleImpl DeriveSymKey(SafeProvHandleImpl providerHandle, SafeHashHandleImpl hashHandle)
		{
			var symKeyHandle = SafeKeyHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptDeriveKey(providerHandle, Constants.CALG_G28147, hashHandle, Constants.CRYPT_EXPORTABLE, ref symKeyHandle))
			{
				throw CreateWin32Error();
			}

			return symKeyHandle;
		}

		public static SafeKeyHandleImpl DuplicateKey(IntPtr sourceKeyHandle)
		{
			var keyHandle = SafeKeyHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptDuplicateKey(sourceKeyHandle, null, 0, ref keyHandle))
			{
				throw CreateWin32Error();
			}

			return keyHandle;
		}

		public static SafeKeyHandleImpl DuplicateKey(SafeKeyHandleImpl sourceKeyHandle)
		{
			return DuplicateKey(sourceKeyHandle.DangerousGetHandle());
		}

		public static int GetKeyParameterInt32(SafeKeyHandleImpl keyHandle, uint keyParamId)
		{
			const int doubleWordSize = 4;

			uint dwDataLength = doubleWordSize;
			var dwDataBytes = new byte[doubleWordSize];

			if (!CryptoApi.CryptGetKeyParam(keyHandle, keyParamId, dwDataBytes, ref dwDataLength, 0))
			{
				throw CreateWin32Error();
			}

			if (dwDataLength != doubleWordSize)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
			}

			return BitConverter.ToInt32(dwDataBytes, 0);
		}

		private static string GetKeyParameterString(SafeKeyHandleImpl keyHandle, uint keyParamId)
		{
			var paramValue = GetKeyParameter(keyHandle, keyParamId);

			return BytesToString(paramValue);
		}

		private static string BytesToString(byte[] value)
		{
			string valueString;

			try
			{
				valueString = Encoding.GetEncoding(0).GetString(value);

				var length = 0;

				while (length < valueString.Length)
				{
					// Строка заканчивается нулевым символом
					if (valueString[length] == '\0')
					{
						break;
					}

					length++;
				}

				if (length == valueString.Length)
				{
					throw ExceptionUtility.CryptographicException(Resources.InvalidString);
				}

				valueString = valueString.Substring(0, length);
			}
			catch (DecoderFallbackException exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.InvalidString);
			}

			return valueString;
		}

		public static byte[] GetKeyParameter(SafeKeyHandleImpl keyHandle, uint keyParamId)
		{
			uint dataLength = 0;

			if (!CryptoApi.CryptGetKeyParam(keyHandle, keyParamId, null, ref dataLength, 0))
			{
				throw CreateWin32Error();
			}

			var dataBytes = new byte[dataLength];

			if (!CryptoApi.CryptGetKeyParam(keyHandle, keyParamId, dataBytes, ref dataLength, 0))
			{
				throw CreateWin32Error();
			}

			return dataBytes;
		}

		public static void SetKeyExchangeExportAlgId(ProviderType providerType, SafeKeyHandleImpl keyHandle, int keyExchangeExportAlgId)
		{
			var keyExchangeExportAlgParamId = providerType.IsVipNet() ? Constants.KP_EXPORTID : Constants.KP_ALGID;
			SetKeyParameterInt32(keyHandle, keyExchangeExportAlgParamId, keyExchangeExportAlgId);
		}

		public static void SetKeyParameterInt32(SafeKeyHandleImpl keyHandle, int keyParamId, int keyParamValue)
		{
			var dwDataBytes = BitConverter.GetBytes(keyParamValue);

			if (!CryptoApi.CryptSetKeyParam(keyHandle, (uint)keyParamId, dwDataBytes, 0))
			{
				throw CreateWin32Error();
			}
		}

		private static void SetKeyParameterString(SafeKeyHandleImpl keyHandle, int keyParamId, string keyParamValue)
		{
			var stringDataBytes = Encoding.GetEncoding(0).GetBytes(keyParamValue);

			if (!CryptoApi.CryptSetKeyParam(keyHandle, (uint)keyParamId, stringDataBytes, 0))
			{
				throw CreateWin32Error();
			}
		}

		public static void SetKeyParameter(SafeKeyHandleImpl keyHandle, int keyParamId, byte[] keyParamValue)
		{
			if (!CryptoApi.CryptSetKeyParam(keyHandle, (uint)keyParamId, keyParamValue, 0))
			{
				throw CreateWin32Error();
			}
		}

		#endregion


		#region Для экспорта ключей криптографического провайдера

		public static byte[] ExportCspBlob(SafeKeyHandleImpl symKeyHandle, SafeKeyHandleImpl keyExchangeHandle, int blobType)
		{
			uint exportedKeyLength = 0;

			if (!CryptoApi.CryptExportKey(symKeyHandle, keyExchangeHandle, (uint)blobType, 0, null, ref exportedKeyLength))
			{
				throw CreateWin32Error();
			}

			var exportedKeyBytes = new byte[exportedKeyLength];

			if (!CryptoApi.CryptExportKey(symKeyHandle, keyExchangeHandle, (uint)blobType, 0, exportedKeyBytes, ref exportedKeyLength))
			{
				throw CreateWin32Error();
			}

			return exportedKeyBytes;
		}

		public static T ExportPublicKey<T>(SafeKeyHandleImpl symKeyHandle, T keyExchangeParams, int keySize) where T : Gost_R3410_KeyExchangeParams
		{
			var exportedKeyBytes = ExportCspBlob(symKeyHandle, SafeKeyHandleImpl.InvalidHandle, Constants.PUBLICKEYBLOB);
			return DecodePublicBlob(exportedKeyBytes, keyExchangeParams, keySize);
		}

		private static T DecodePublicBlob<T>(byte[] encodedPublicBlob, T keyExchangeParams, int keySize) where T : Gost_R3410_KeyExchangeParams
		{
			if (encodedPublicBlob == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(encodedPublicBlob));
			}

			if (encodedPublicBlob.Length < 16 + keySize / 8)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
			}

			var gostKeyMask = BitConverter.ToUInt32(encodedPublicBlob, 8);

			if (gostKeyMask != Constants.GR3410_1_MAGIC)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
			}

			var gostKeySize = BitConverter.ToUInt32(encodedPublicBlob, 12);

			if (gostKeySize != keySize)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
			}

			var encodeKeyParameters = new byte[encodedPublicBlob.Length - 16 - keySize / 8];
			Array.Copy(encodedPublicBlob, 16, encodeKeyParameters, 0, encodedPublicBlob.Length - 16 - keySize / 8);
			keyExchangeParams.DecodeParameters(encodeKeyParameters);

			var publicKey = new byte[keySize / 8];
			Array.Copy(encodedPublicBlob, encodedPublicBlob.Length - keySize / 8, publicKey, 0, keySize / 8);
			keyExchangeParams.PublicKey = publicKey;

			return keyExchangeParams;
		}

		public static Gost_28147_89_KeyExchangeInfo ExportKeyExchange(SafeKeyHandleImpl symKeyHandle, SafeKeyHandleImpl keyExchangeHandle)
		{
			var exportedKeyBytes = ExportCspBlob(symKeyHandle, keyExchangeHandle, Constants.SIMPLEBLOB);

			return DecodeSimpleBlob(exportedKeyBytes);
		}

		private static Gost_28147_89_KeyExchangeInfo DecodeSimpleBlob(byte[] exportedKeyBytes)
		{
			if (exportedKeyBytes == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(exportedKeyBytes));
			}

			if (exportedKeyBytes.Length < 16)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
			}

			if (BitConverter.ToUInt32(exportedKeyBytes, 4) != Constants.CALG_G28147)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
			}

			if (BitConverter.ToUInt32(exportedKeyBytes, 8) != Constants.G28147_MAGIC)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
			}

			if (BitConverter.ToUInt32(exportedKeyBytes, 12) != Constants.CALG_G28147)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
			}

			var keyExchangeInfo = new Gost_28147_89_KeyExchangeInfo();

			var sourceIndex = 16;
			keyExchangeInfo.Ukm = new byte[8];
			Array.Copy(exportedKeyBytes, sourceIndex, keyExchangeInfo.Ukm, 0, 8);
			sourceIndex += 8;

			keyExchangeInfo.EncryptedKey = new byte[32];
			Array.Copy(exportedKeyBytes, sourceIndex, keyExchangeInfo.EncryptedKey, 0, 32);
			sourceIndex += 32;

			keyExchangeInfo.Mac = new byte[4];
			Array.Copy(exportedKeyBytes, sourceIndex, keyExchangeInfo.Mac, 0, 4);
			sourceIndex += 4;

			var encryptionParamSet = new byte[exportedKeyBytes.Length - sourceIndex];
			Array.Copy(exportedKeyBytes, sourceIndex, encryptionParamSet, 0, exportedKeyBytes.Length - sourceIndex);
			keyExchangeInfo.EncryptionParamSet = Gost_28147_89_KeyExchangeInfo.DecodeEncryptionParamSet(encryptionParamSet);

			return keyExchangeInfo;
		}

		#endregion


		#region Для импорта ключей криптографического провайдера

		public static int ImportCspBlob(byte[] importedKeyBytes, SafeProvHandleImpl providerHandle, SafeKeyHandleImpl publicKeyHandle, out SafeKeyHandleImpl keyExchangeHandle)
		{
			var dwFlags = MapCspKeyFlags(CspProviderFlags.NoFlags);
			var keyExchangeRef = SafeKeyHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptImportKey(providerHandle, importedKeyBytes, (uint)importedKeyBytes.Length, publicKeyHandle, dwFlags, ref keyExchangeRef))
			{
				throw CreateWin32Error();
			}

			var keyNumberMask = BitConverter.ToInt32(importedKeyBytes, 4) & 0xE000;
			var keyNumber = (keyNumberMask == 0xA000) ? Constants.AT_KEYEXCHANGE : Constants.AT_SIGNATURE;

			keyExchangeHandle = keyExchangeRef;

			return keyNumber;
		}

		[SecurityCritical]
		public static byte[] EncodePublicBlob(Gost_R3410_KeyExchangeParams publicKeyParameters, int keySize, int signatureAlgId)
		{
			var encodedKeyParams = publicKeyParameters.EncodeParameters();
			var encodedKeyBlob = new byte[16 + encodedKeyParams.Length + publicKeyParameters.PublicKey.Length];
			encodedKeyBlob[0] = 6;
			encodedKeyBlob[1] = 32;
			Array.Copy(BitConverter.GetBytes(signatureAlgId), 0, encodedKeyBlob, 4, 4);
			Array.Copy(BitConverter.GetBytes(Constants.GR3410_1_MAGIC), 0, encodedKeyBlob, 8, 4);
			Array.Copy(BitConverter.GetBytes(keySize), 0, encodedKeyBlob, 12, 4);
			Array.Copy(encodedKeyParams, 0, encodedKeyBlob, 16, encodedKeyParams.Length);
			Array.Copy(publicKeyParameters.PublicKey, 0, encodedKeyBlob, 16 + encodedKeyParams.Length, publicKeyParameters.PublicKey.Length);

			return encodedKeyBlob;
		}

		public static SafeKeyHandleImpl ImportKeyExchange(SafeProvHandleImpl providerHandle, Gost_28147_89_KeyExchangeInfo keyExchangeInfo, SafeKeyHandleImpl keyExchangeHandle)
		{
			if (keyExchangeInfo == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyExchangeInfo));
			}

			var importedKeyBytes = EncodeSimpleBlob(keyExchangeInfo);

			SafeKeyHandleImpl hKeyExchange;
			ImportCspBlob(importedKeyBytes, providerHandle, keyExchangeHandle, out hKeyExchange);

			return hKeyExchange;
		}

		public static SafeKeyHandleImpl ImportBulkSessionKey(ProviderType providerType, SafeProvHandleImpl providerHandle, byte[] bulkSessionKey, RNGCryptoServiceProvider randomNumberGenerator)
		{
			if (bulkSessionKey == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(bulkSessionKey));
			}

			if (randomNumberGenerator == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(randomNumberGenerator));
			}

			var hSessionKey = SafeKeyHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptGenKey(providerHandle, Constants.CALG_G28147, 0, ref hSessionKey))
			{
				throw CreateWin32Error();
			}

			var keyWrap = new Gost_28147_89_KeyExchangeInfo { EncryptedKey = new byte[32] };
			Array.Copy(bulkSessionKey, keyWrap.EncryptedKey, 32);
			SetKeyParameterInt32(hSessionKey, Constants.KP_MODE, Constants.CRYPT_MODE_ECB);
			SetKeyParameterInt32(hSessionKey, Constants.KP_ALGID, Constants.CALG_G28147);
			SetKeyParameterInt32(hSessionKey, Constants.KP_PADDING, Constants.ZERO_PADDING);

			uint sessionKeySize = 32;

			if (!CryptoApi.CryptEncrypt(hSessionKey, SafeHashHandleImpl.InvalidHandle, true, 0, keyWrap.EncryptedKey, ref sessionKeySize, sessionKeySize))
			{
				throw CreateWin32Error();
			}

			SetKeyParameterInt32(hSessionKey, Constants.KP_MODE, Constants.CRYPT_MODE_CFB);

			var hashHandle = CreateHashImit(providerHandle, hSessionKey);

			keyWrap.Ukm = new byte[8];
			randomNumberGenerator.GetBytes(keyWrap.Ukm);

			if (!CryptoApi.CryptSetHashParam(hashHandle, Constants.HP_HASHSTARTVECT, keyWrap.Ukm, 0))
			{
				throw CreateWin32Error();
			}

			if (!CryptoApi.CryptHashData(hashHandle, bulkSessionKey, 32, 0))
			{
				throw CreateWin32Error();
			}

			keyWrap.Mac = EndHashData(hashHandle);
			keyWrap.EncryptionParamSet = GetKeyParameterString(hSessionKey, Constants.KP_CIPHEROID);

			SetKeyExchangeExportAlgId(providerType, hSessionKey, Constants.CALG_SIMPLE_EXPORT);
			SetKeyParameterInt32(hSessionKey, Constants.KP_MODE, Constants.CRYPT_MODE_ECB);
			SetKeyParameterInt32(hSessionKey, Constants.KP_PADDING, Constants.ZERO_PADDING);

			return ImportKeyExchange(providerHandle, keyWrap, hSessionKey);
		}

		private static byte[] EncodeSimpleBlob(Gost_28147_89_KeyExchangeInfo keyExchangeInfo)
		{
			if (keyExchangeInfo == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyExchangeInfo));
			}

			var encryptionParamSet = Gost_28147_89_KeyExchangeInfo.EncodeEncryptionParamSet(keyExchangeInfo.EncryptionParamSet);
			var importedKeyBytes = new byte[encryptionParamSet.Length + 60];

			var sourceIndex = 0;
			importedKeyBytes[sourceIndex] = 1;
			sourceIndex++;

			importedKeyBytes[sourceIndex] = 32;
			sourceIndex++;
			sourceIndex += 2;

			Array.Copy(BitConverter.GetBytes(Constants.CALG_G28147), 0, importedKeyBytes, sourceIndex, 4);
			sourceIndex += 4;

			Array.Copy(BitConverter.GetBytes(Constants.G28147_MAGIC), 0, importedKeyBytes, sourceIndex, 4);
			sourceIndex += 4;

			Array.Copy(BitConverter.GetBytes(Constants.CALG_G28147), 0, importedKeyBytes, sourceIndex, 4);
			sourceIndex += 4;

			Array.Copy(keyExchangeInfo.Ukm, 0, importedKeyBytes, sourceIndex, 8);
			sourceIndex += 8;

			Array.Copy(keyExchangeInfo.EncryptedKey, 0, importedKeyBytes, sourceIndex, 32);
			sourceIndex += 32;

			Array.Copy(keyExchangeInfo.Mac, 0, importedKeyBytes, sourceIndex, 4);
			sourceIndex += 4;

			Array.Copy(encryptionParamSet, 0, importedKeyBytes, sourceIndex, encryptionParamSet.Length);

			return importedKeyBytes;
		}

		#endregion


		#region Для работы с цифровой подписью

		public static byte[] SignValue(SafeProvHandleImpl providerHandle, SafeHashHandleImpl hashHandle, int keyNumber, byte[] hashValue)
		{
			SetHashValue(hashHandle, hashValue);

			uint signatureLength = 0;

			// Вычисление размера подписи
			if (!CryptoApi.CryptSignHash(hashHandle, (uint)keyNumber, null, 0, null, ref signatureLength))
			{
				throw CreateWin32Error();
			}

			var signatureValue = new byte[signatureLength];

			// Вычисление значения подписи
			if (!CryptoApi.CryptSignHash(hashHandle, (uint)keyNumber, null, 0, signatureValue, ref signatureLength))
			{
				throw CreateWin32Error();
			}

			return signatureValue;
		}

		public static bool VerifySign(SafeProvHandleImpl providerHandle, SafeHashHandleImpl hashHandle, SafeKeyHandleImpl keyHandle, byte[] hashValue, byte[] signatureValue)
		{
			SetHashValue(hashHandle, hashValue);

			return CryptoApi.CryptVerifySignature(hashHandle, signatureValue, (uint)signatureValue.Length, keyHandle, null, 0);
		}

		private static void SetHashValue(SafeHashHandleImpl hashHandle, byte[] hashValue)
		{
			uint hashLength = 0;

			if (!CryptoApi.CryptGetHashParam(hashHandle, Constants.HP_HASHVAL, null, ref hashLength, 0))
			{
				throw CreateWin32Error();
			}

			if (hashValue.Length != hashLength)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_HASH);
			}

			if (!CryptoApi.CryptSetHashParam(hashHandle, Constants.HP_HASHVAL, hashValue, 0))
			{
				throw CreateWin32Error();
			}
		}

		#endregion


		public static T DangerousAddRef<T>(this T handle) where T : SafeHandle
		{
			var success = false;
			handle.DangerousAddRef(ref success);

			return handle;
		}

		public static void TryDispose(this SafeHandle handle)
		{
			if ((handle != null) && !handle.IsClosed)
			{
				handle.Dispose();
			}
		}

		private static CryptographicException CreateWin32Error()
		{
			return ExceptionUtility.CryptographicException(Marshal.GetLastWin32Error());
		}
	}
}