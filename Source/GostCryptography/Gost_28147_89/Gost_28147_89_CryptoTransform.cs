using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;

using GostCryptography.Base;
using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Gost_28147_89
{
	/// <summary>
	/// Реализует криптографическое преобразование с использованием алгоритма симметричного шифрования ГОСТ 28147-89.
	/// </summary>
	sealed class Gost_28147_89_CryptoTransform : ICryptoTransform
	{
		[SecurityCritical]
		public Gost_28147_89_CryptoTransform(
			ProviderType providerType,
			SafeKeyHandleImpl keyHandle,
			Dictionary<int, object> keyParameters,
			PaddingMode paddingValue,
			CipherMode modeValue,
			int blockSizeValue,
			Gost_28147_89_CryptoTransformMode transformMode)
		{
			_providerType = providerType;
			_keyHandle = keyHandle;
			_paddingValue = paddingValue;
			_isStreamModeValue = (modeValue == CipherMode.OFB) || (modeValue == CipherMode.CFB);
			_blockSizeValue = blockSizeValue;
			_transformMode = transformMode;

			// Установка параметров ключа

			foreach (var keyParameter in keyParameters)
			{
				var keyParameterId = keyParameter.Key;
				var keyParameterValue = keyParameter.Value;

				// Копирование значения параметра

				if (keyParameterValue is byte[])
				{
					var keyParamValueBytes = (byte[])keyParameterValue;
					var copyKeyParamValueBytes = new byte[keyParamValueBytes.Length];
					Array.Copy(keyParamValueBytes, copyKeyParamValueBytes, keyParamValueBytes.Length);

					keyParameterValue = copyKeyParamValueBytes;
				}
				else if (keyParameterValue is int)
				{
					keyParameterValue = (int)keyParameterValue;
				}
				else if (keyParameterValue is CipherMode)
				{
					keyParameterValue = Convert.ToInt32(keyParameterValue);
				}
				else if (keyParameterValue is PaddingMode)
				{
					keyParameterValue = Convert.ToInt32(keyParameterValue);
				}

				// Установка значения параметра

				switch (keyParameterId)
				{
					case Constants.KP_IV:
						{
							_ivValue = (byte[])keyParameterValue;

							var iv = _ivValue;
							CryptoApiHelper.SetKeyParameter(_keyHandle, keyParameterId, iv);
						}
						break;
					case Constants.KP_MODE:
						{
							CryptoApiHelper.SetKeyParameterInt32(_keyHandle, keyParameterId, (int)keyParameterValue);
						}
						break;
					case Constants.KP_PADDING:
						{
							if (!providerType.IsVipNet())
							{
								CryptoApiHelper.SetKeyParameterInt32(_keyHandle, keyParameterId, (int)keyParameterValue);
							}
						}
						break;
				}
			}
		}

		private readonly ProviderType _providerType;

		[SecurityCritical]
		private readonly SafeKeyHandleImpl _keyHandle;

		private readonly PaddingMode _paddingValue;
		private readonly bool _isStreamModeValue;
		private readonly int _blockSizeValue;
		private readonly Gost_28147_89_CryptoTransformMode _transformMode;

		private byte[] _dataBuffer;
		private byte[] _ivValue;


		public bool CanReuseTransform => true;

		public bool CanTransformMultipleBlocks => true;

		public int InputBlockSize => (_blockSizeValue / 8);

		public int OutputBlockSize => (_blockSizeValue / 8);


		[SecuritySafeCritical]
		public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
		{
			if (inputBuffer == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(inputBuffer));
			}

			if (outputBuffer == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(outputBuffer));
			}

			if (inputOffset < 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(inputOffset));
			}

			if ((inputCount <= 0) || ((inputCount % InputBlockSize) != 0) || (inputCount > inputBuffer.Length))
			{
				throw ExceptionUtility.Argument(nameof(inputOffset), Resources.InvalidDataOffset);
			}

			if ((inputBuffer.Length - inputCount) < inputOffset)
			{
				throw ExceptionUtility.Argument(nameof(inputOffset), Resources.InvalidDataOffset);
			}

			if (_transformMode == Gost_28147_89_CryptoTransformMode.Encrypt)
			{
				return CryptoApiHelper.EncryptData(_providerType, _keyHandle, inputBuffer, inputOffset, inputCount, ref outputBuffer, outputOffset, _paddingValue, false, _isStreamModeValue);
			}

			if ((_paddingValue == PaddingMode.Zeros) || (_paddingValue == PaddingMode.None))
			{
				return CryptoApiHelper.DecryptData(_keyHandle, inputBuffer, inputOffset, inputCount, ref outputBuffer, outputOffset, _paddingValue, false);
			}

			int dectyptDataLength;

			if (_dataBuffer == null)
			{
				_dataBuffer = new byte[InputBlockSize];

				var length = inputCount - InputBlockSize;
				Array.Copy(inputBuffer, inputOffset + length, _dataBuffer, 0, InputBlockSize);

				dectyptDataLength = CryptoApiHelper.DecryptData(_keyHandle, inputBuffer, inputOffset, length, ref outputBuffer, outputOffset, _paddingValue, false);
			}
			else
			{
				CryptoApiHelper.DecryptData(_keyHandle, _dataBuffer, 0, _dataBuffer.Length, ref outputBuffer, outputOffset, _paddingValue, false);

				outputOffset += OutputBlockSize;

				var length = inputCount - InputBlockSize;
				Array.Copy(inputBuffer, inputOffset + length, _dataBuffer, 0, InputBlockSize);

				dectyptDataLength = OutputBlockSize + CryptoApiHelper.DecryptData(_keyHandle, inputBuffer, inputOffset, length, ref outputBuffer, outputOffset, _paddingValue, false);
			}

			return dectyptDataLength;
		}

		[SecuritySafeCritical]
		public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
		{
			if (inputBuffer == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(inputBuffer));
			}

			if (inputOffset < 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(inputOffset));
			}

			if ((inputCount < 0) || (inputCount > inputBuffer.Length))
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(inputOffset), Resources.InvalidDataOffset);
			}

			if ((inputBuffer.Length - inputCount) < inputOffset)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(inputOffset), Resources.InvalidDataOffset);
			}

			byte[] buffer = null;

			if (_transformMode == Gost_28147_89_CryptoTransformMode.Encrypt)
			{
				CryptoApiHelper.EncryptData(_providerType, _keyHandle, inputBuffer, inputOffset, inputCount, ref buffer, 0, _paddingValue, true, _isStreamModeValue);
				Reset();
				return buffer;
			}

			if (_isStreamModeValue)
			{
				CryptoApiHelper.DecryptData(_keyHandle, inputBuffer, inputOffset, inputCount, ref buffer, 0, _paddingValue, true);
				Reset();
				return buffer;
			}

			if ((inputCount % InputBlockSize) != 0)
			{
				throw ExceptionUtility.CryptographicException(Resources.DecryptInvalidDataSize);
			}

			if (_dataBuffer == null)
			{
				CryptoApiHelper.DecryptData(_keyHandle, inputBuffer, inputOffset, inputCount, ref buffer, 0, _paddingValue, true);
				Reset();
				return buffer;
			}

			var destinationArray = new byte[_dataBuffer.Length + inputCount];
			Array.Copy(_dataBuffer, 0, destinationArray, 0, _dataBuffer.Length);
			Array.Copy(inputBuffer, inputOffset, destinationArray, _dataBuffer.Length, inputCount);

			CryptoApiHelper.DecryptData(_keyHandle, destinationArray, 0, destinationArray.Length, ref buffer, 0, _paddingValue, true);
			Reset();
			return buffer;
		}


		[SecuritySafeCritical]
		private void Reset()
		{
			_dataBuffer = null;

			if (_transformMode == Gost_28147_89_CryptoTransformMode.Encrypt)
			{
				CryptoApiHelper.EndEncrypt(_providerType, _keyHandle);
			}
			else
			{
				CryptoApiHelper.EndDecrypt(_providerType, _keyHandle);
			}
		}


		[SecuritySafeCritical]
		private void Dispose(bool disposing)
		{
			if (disposing)
			{
				if (_ivValue != null)
				{
					Array.Clear(_ivValue, 0, _ivValue.Length);
					_ivValue = null;
				}

				if (_dataBuffer != null)
				{
					Array.Clear(_dataBuffer, 0, _dataBuffer.Length);
					_dataBuffer = null;
				}
			}

			_keyHandle.TryDispose();
		}

		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		~Gost_28147_89_CryptoTransform()
		{
			Dispose(false);
		}
	}
}