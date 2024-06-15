using System.Security;
using System.Security.Cryptography;

using GostCryptography.Asn1.Gost.Gost_28147_89;
using GostCryptography.Asn1.Gost.Gost_R3410;
using GostCryptography.Base;
using GostCryptography.Gost_28147_89;
using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Базовый класс всех реализаций общего секретного ключа ГОСТ Р 34.10.
	/// </summary>
	public abstract class Gost_R3410_KeyExchangeAlgorithm : GostKeyExchangeAlgorithm
	{
		/// <inheritdoc />
		[SecurityCritical]
		protected Gost_R3410_KeyExchangeAlgorithm(ProviderType providerType, SafeProvHandleImpl provHandle, SafeKeyHandleImpl keyHandle, Gost_R3410_KeyExchangeParams keyExchangeParameters, int keySize, int signatureAlgId) : base(providerType)
		{
			if (provHandle == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(provHandle));
			}

			if (keyHandle == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyHandle));
			}

			if (keyExchangeParameters == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyExchangeParameters));
			}

			_provHandle = provHandle.DangerousAddRef();
			_keyHandle = keyHandle.DangerousAddRef();
			_keyExchangeParameters = keyExchangeParameters;
			_keySize = keySize;
			_signatureAlgId = signatureAlgId;
		}


		[SecurityCritical]
		private readonly SafeProvHandleImpl _provHandle;
		[SecurityCritical]
		private readonly SafeKeyHandleImpl _keyHandle;
		[SecurityCritical]
		private readonly Gost_R3410_KeyExchangeParams _keyExchangeParameters;

		private readonly int _keySize;
		private readonly int _signatureAlgId;


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override byte[] EncodeKeyExchange(SymmetricAlgorithm keyExchangeAlgorithm, GostKeyExchangeExportMethod keyExchangeExportMethod)
		{
			int exportAlgId;

			if (keyExchangeAlgorithm is ISafeHandleProvider<SafeKeyHandleImpl> exportKey)
			{
				switch (keyExchangeExportMethod)
				{
					case GostKeyExchangeExportMethod.GostKeyExport:
						exportAlgId = Constants.CALG_SIMPLE_EXPORT;
						break;
					case GostKeyExchangeExportMethod.CryptoProKeyExport:
						exportAlgId = Constants.CALG_PRO_EXPORT;
						break;
					case GostKeyExchangeExportMethod.CryptoProTk26KeyExport:
						exportAlgId = Constants.CALG_PRO12_EXPORT;
						break;
					default:
						throw ExceptionUtility.ArgumentOutOfRange(nameof(keyExchangeExportMethod));
				}
			}
			else
			{
				throw ExceptionUtility.Argument(nameof(keyExchangeAlgorithm), Resources.RequiredGost28147);
			}

			return EncodeKeyExchangeInternal(exportKey, exportAlgId);
		}

		[SecurityCritical]
		private byte[] EncodeKeyExchangeInternal(ISafeHandleProvider<SafeKeyHandleImpl> exportKey, int exportAlgId)
		{
			Gost_28147_89_KeyExchangeInfo keyExchangeInfo;

			SafeKeyHandleImpl keyExchangeHandle = null;

			try
			{
				var importedKeyBytes = CryptoApiHelper.EncodePublicBlob(_keyExchangeParameters, _keySize, _signatureAlgId);
				CryptoApiHelper.ImportCspBlob(importedKeyBytes, _provHandle, _keyHandle, out keyExchangeHandle);
				CryptoApiHelper.SetKeyExchangeExportAlgId(ProviderType, keyExchangeHandle, exportAlgId);

				var symKeyHandle = exportKey.GetSafeHandle();
				keyExchangeInfo = CryptoApiHelper.ExportKeyExchange(symKeyHandle, keyExchangeHandle);
			}
			finally
			{
				keyExchangeHandle.TryDispose();
			}

			return keyExchangeInfo.Encode();
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override SymmetricAlgorithm DecodeKeyExchange(byte[] encodedKeyExchangeData, GostKeyExchangeExportMethod keyExchangeExportMethod)
		{
			switch (keyExchangeExportMethod)
			{
				case GostKeyExchangeExportMethod.GostKeyExport:
					return DecodeKeyExchangeInternal(encodedKeyExchangeData, Constants.CALG_SIMPLE_EXPORT);
				case GostKeyExchangeExportMethod.CryptoProKeyExport:
					return DecodeKeyExchangeInternal(encodedKeyExchangeData, Constants.CALG_PRO_EXPORT);
				case GostKeyExchangeExportMethod.CryptoProTk26KeyExport:
					return DecodeKeyExchangeInternal(encodedKeyExchangeData, Constants.CALG_PRO12_EXPORT);
				default:
					throw ExceptionUtility.ArgumentOutOfRange(nameof(keyExchangeExportMethod));
			}
		}

		[SecurityCritical]
		private SymmetricAlgorithm DecodeKeyExchangeInternal(byte[] encodedKeyExchangeData, int keyExchangeExportAlgId)
		{
			var keyExchangeInfo = new Gost_28147_89_KeyExchangeInfo();
			keyExchangeInfo.Decode(encodedKeyExchangeData);

			SafeKeyHandleImpl symKeyHandle;
			SafeKeyHandleImpl keyExchangeHandle = null;

			try
			{
				var importedKeyBytes = CryptoApiHelper.EncodePublicBlob(_keyExchangeParameters, _keySize, _signatureAlgId);
				CryptoApiHelper.ImportCspBlob(importedKeyBytes, _provHandle, _keyHandle, out keyExchangeHandle);
				CryptoApiHelper.SetKeyExchangeExportAlgId(ProviderType, keyExchangeHandle, keyExchangeExportAlgId);

				symKeyHandle = CryptoApiHelper.ImportKeyExchange(_provHandle, keyExchangeInfo, keyExchangeHandle);
			}
			finally
			{
				keyExchangeHandle.TryDispose();
			}

			if (keyExchangeInfo.EncryptionParamSet == Gost_28147_89_Constants.EncryptAlgorithm.Value)
			{
				return new Gost_28147_89_SymmetricAlgorithm(ProviderType, _provHandle, symKeyHandle);
			}
			else if (keyExchangeInfo.EncryptionParamSet == Gost_28147_89_Constants.EncryptAlgorithmMagma.Value)
			{
				return new Gost_3412_M_SymmetricAlgorithm(ProviderType, _provHandle, symKeyHandle);
			}
			else if (keyExchangeInfo.EncryptionParamSet == Gost_28147_89_Constants.EncryptAlgorithmKuznyechik.Value)
			{
				return new Gost_3412_K_SymmetricAlgorithm(ProviderType, _provHandle, symKeyHandle);
			}
			else
			{
				return new Gost_28147_89_SymmetricAlgorithm(ProviderType, _provHandle, symKeyHandle);
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