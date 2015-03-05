using System;
using System.Security;
using System.Security.Cryptography;

using GostCryptography.Asn1.Common;
using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Реализация общего секретного ключа.
	/// </summary>
	sealed class GostKeyExchangeAlgorithm : GostKeyExchangeAlgorithmBase
	{
		[SecurityCritical]
		public GostKeyExchangeAlgorithm(SafeProvHandleImpl provHandle, SafeKeyHandleImpl keyHandle, GostKeyExchangeParameters keyExchangeParameters)
		{
			if (provHandle == null)
			{
				throw ExceptionUtility.ArgumentNull("provHandle");
			}

			if (keyHandle == null)
			{
				throw ExceptionUtility.ArgumentNull("keyHandle");
			}

			if (keyExchangeParameters == null)
			{
				throw ExceptionUtility.ArgumentNull("keyExchangeParameters");
			}

			_provHandle = provHandle.DangerousAddRef();
			_keyHandle = keyHandle.DangerousAddRef();
			_keyExchangeParameters = keyExchangeParameters;
		}


		[SecurityCritical]
		private readonly SafeProvHandleImpl _provHandle;

		[SecurityCritical]
		private readonly SafeKeyHandleImpl _keyHandle;

		private readonly GostKeyExchangeParameters _keyExchangeParameters;


		/// <summary>
		/// Экспортирует (шифрует) общий секретный ключ.
		/// </summary>
		/// <param name="keyExchangeAlgorithm">Общий секретный ключ.</param>
		/// <param name="keyExchangeExportMethod">Алгоритм экспорта общего секретного ключа.</param>
		/// <exception cref="ArgumentException"></exception>
		[SecuritySafeCritical]
		public override byte[] EncodeKeyExchange(SymmetricAlgorithm keyExchangeAlgorithm, GostKeyExchangeExportMethod keyExchangeExportMethod)
		{
			if (keyExchangeAlgorithm is Gost28147SymmetricAlgorithm)
			{
				return EncodeKeyExchangeInternal((Gost28147SymmetricAlgorithm)keyExchangeAlgorithm, keyExchangeExportMethod);
			}

			if (keyExchangeAlgorithm is Gost28147SymmetricAlgorithmBase)
			{
				using (var gostKeyExchangeAlgorithm = new Gost28147SymmetricAlgorithm())
				{
					return gostKeyExchangeAlgorithm.EncodePrivateKey((Gost28147SymmetricAlgorithmBase)keyExchangeAlgorithm, keyExchangeExportMethod);
				}
			}

			throw ExceptionUtility.Argument("keyExchangeAlgorithm", Resources.RequiredGost28147);
		}

		[SecurityCritical]
		private byte[] EncodeKeyExchangeInternal(Gost28147SymmetricAlgorithm keyExchangeAlgorithm, GostKeyExchangeExportMethod keyExchangeExportMethod)
		{
			switch (keyExchangeExportMethod)
			{
				case GostKeyExchangeExportMethod.GostKeyExport:
					return EncodeKeyExchangeInternal(keyExchangeAlgorithm, Constants.CALG_SIMPLE_EXPORT);

				case GostKeyExchangeExportMethod.CryptoProKeyExport:
					return EncodeKeyExchangeInternal(keyExchangeAlgorithm, Constants.CALG_PRO_EXPORT);
			}

			throw ExceptionUtility.ArgumentOutOfRange("keyExchangeExportMethod");
		}

		[SecurityCritical]
		private byte[] EncodeKeyExchangeInternal(Gost28147SymmetricAlgorithm keyExchangeAlgorithm, int keyExchangeExportAlgId)
		{
			GostKeyExchangeInfo keyExchangeInfo;

			SafeKeyHandleImpl keyExchangeHandle = null;

			try
			{
				keyExchangeHandle = CryptoApiHelper.ImportAndMakeKeyExchange(_provHandle, _keyExchangeParameters, _keyHandle);
				CryptoApiHelper.SetKeyParameterInt32(keyExchangeHandle, Constants.KP_ALGID, keyExchangeExportAlgId);

				var symKeyHandle = keyExchangeAlgorithm.InternalKeyHandle;
				keyExchangeInfo = CryptoApiHelper.ExportKeyExchange(symKeyHandle, keyExchangeHandle);
			}
			finally
			{
				keyExchangeHandle.TryDispose();
			}

			return keyExchangeInfo.Encode();
		}


		/// <summary>
		/// Импортирует (дешифрует) общий секретный ключ.
		/// </summary>
		/// <param name="encodedKeyExchangeData">Общий секретный ключ.</param>
		/// <param name="keyExchangeExportMethod">Алгоритм экспорта общего секретного ключа.</param>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		[SecuritySafeCritical]
		public override SymmetricAlgorithm DecodeKeyExchange(byte[] encodedKeyExchangeData, GostKeyExchangeExportMethod keyExchangeExportMethod)
		{
			new GostKeyExchangeInfo().Decode(encodedKeyExchangeData);

			switch (keyExchangeExportMethod)
			{
				case GostKeyExchangeExportMethod.GostKeyExport:
					return DecodeKeyExchangeInternal(encodedKeyExchangeData, Constants.CALG_SIMPLE_EXPORT);

				case GostKeyExchangeExportMethod.CryptoProKeyExport:
					return DecodeKeyExchangeInternal(encodedKeyExchangeData, Constants.CALG_PRO_EXPORT);
			}

			throw ExceptionUtility.ArgumentOutOfRange("keyExchangeExportMethod");
		}

		[SecurityCritical]
		private SymmetricAlgorithm DecodeKeyExchangeInternal(byte[] encodedKeyExchangeData, int keyExchangeExportAlgId)
		{
			var keyExchangeInfo = new GostKeyExchangeInfo();
			keyExchangeInfo.Decode(encodedKeyExchangeData);

			SafeKeyHandleImpl symKeyHandle;
			SafeKeyHandleImpl keyExchangeHandle = null;

			try
			{
				keyExchangeHandle = CryptoApiHelper.ImportAndMakeKeyExchange(_provHandle, _keyExchangeParameters, _keyHandle);
				CryptoApiHelper.SetKeyParameterInt32(keyExchangeHandle, Constants.KP_ALGID, keyExchangeExportAlgId);

				symKeyHandle = CryptoApiHelper.ImportKeyExchange(_provHandle, keyExchangeInfo, keyExchangeHandle);
			}
			finally
			{
				keyExchangeHandle.TryDispose();
			}

			return new Gost28147SymmetricAlgorithm(_provHandle, symKeyHandle);
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