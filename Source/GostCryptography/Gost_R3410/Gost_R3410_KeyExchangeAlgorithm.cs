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
			if (keyExchangeAlgorithm is Gost_28147_89_SymmetricAlgorithm symAlg)
			{
				return EncodeKeyExchangeInternal(symAlg, keyExchangeExportMethod);
			}

			if (keyExchangeAlgorithm is Gost_28147_89_SymmetricAlgorithmBase symAlgBase)
			{
				using (var gostKeyExchangeAlgorithm = new Gost_28147_89_SymmetricAlgorithm(symAlgBase.ProviderType))
				{
					return gostKeyExchangeAlgorithm.EncodePrivateKey(symAlgBase, keyExchangeExportMethod);
				}
			}

			throw ExceptionUtility.Argument(nameof(keyExchangeAlgorithm), Resources.RequiredGost28147);
		}

		[SecurityCritical]
		private byte[] EncodeKeyExchangeInternal(Gost_28147_89_SymmetricAlgorithm keyExchangeAlgorithm, GostKeyExchangeExportMethod keyExchangeExportMethod)
		{
			switch (keyExchangeExportMethod)
			{
				case GostKeyExchangeExportMethod.GostKeyExport:
					return EncodeKeyExchangeInternal(keyExchangeAlgorithm, Constants.CALG_SIMPLE_EXPORT);

				case GostKeyExchangeExportMethod.CryptoProKeyExport:
					return EncodeKeyExchangeInternal(keyExchangeAlgorithm, Constants.CALG_PRO_EXPORT);
			}

			throw ExceptionUtility.ArgumentOutOfRange(nameof(keyExchangeExportMethod));
		}

		[SecurityCritical]
		private byte[] EncodeKeyExchangeInternal(Gost_28147_89_SymmetricAlgorithm keyExchangeAlgorithm, int keyExchangeExportAlgId)
		{
			Gost_28147_89_KeyExchangeInfo keyExchangeInfo;

			SafeKeyHandleImpl keyExchangeHandle = null;

			try
			{
				var importedKeyBytes = CryptoApiHelper.EncodePublicBlob(_keyExchangeParameters, _keySize, _signatureAlgId);
				CryptoApiHelper.ImportCspBlob(importedKeyBytes, _provHandle, _keyHandle, out keyExchangeHandle);
				CryptoApiHelper.SetKeyExchangeExportAlgId(ProviderType, keyExchangeHandle, keyExchangeExportAlgId);

				var symKeyHandle = keyExchangeAlgorithm.GetSafeHandle();
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
			}

			throw ExceptionUtility.ArgumentOutOfRange(nameof(keyExchangeExportMethod));
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

			return new Gost_28147_89_SymmetricAlgorithm(ProviderType, _provHandle, symKeyHandle);
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