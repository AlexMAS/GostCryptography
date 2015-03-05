using System;

using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Encryption.Gost2814789;
using GostCryptography.Asn1.PKI.GostR34102001;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Common
{
	/// <summary>
	/// Параметры алгоритма цифровой подписи ГОСТ Р 34.10 и алгоритма формирования общего секретного ключа, включая открытый ключ.
	/// </summary>
	public sealed class GostKeyExchangeParameters
	{
		public GostKeyExchangeParameters()
		{
		}

		public GostKeyExchangeParameters(GostKeyExchangeParameters parameters)
		{
			DigestParamSet = parameters.DigestParamSet;
			PublicKeyParamSet = parameters.PublicKeyParamSet;
			EncryptionParamSet = parameters.EncryptionParamSet;
			PublicKey = parameters.PublicKey;
			PrivateKey = parameters.PrivateKey;
		}


		/// <summary>
		/// Идентификатор OID параметров хэширования.
		/// </summary>
		public string DigestParamSet;

		/// <summary>
		/// Идентификатор OID параметров открытого ключа.
		/// </summary>
		public string PublicKeyParamSet;

		/// <summary>
		/// Идентификатор OID параметров шифрования.
		/// </summary>
		public string EncryptionParamSet;

		/// <summary>
		/// Открытый ключ.
		/// </summary>
		public byte[] PublicKey;

		/// <summary>
		/// Закрытый ключ.
		/// </summary>
		public byte[] PrivateKey;


		public void DecodeParameters(byte[] data)
		{
			if (data == null)
			{
				throw ExceptionUtility.ArgumentNull("data");
			}

			try
			{
				var asnDecoder = new Asn1BerDecodeBuffer(data);
				var publicKeyParameters = new GostR34102001PublicKeyParameters();
				publicKeyParameters.Decode(asnDecoder);

				DigestParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParameters.DigestParamSet);
				PublicKeyParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParameters.PublicKeyParamSet);
				EncryptionParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParameters.EncryptionParamSet);
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, typeof(GostR34102001PublicKeyParameters).FullName);
			}
		}


		public byte[] EncodeParameters()
		{
			byte[] data;

			var publicKeyParameters = new GostR34102001PublicKeyParameters();

			try
			{
				publicKeyParameters.DigestParamSet = Asn1ObjectIdentifier.FromOidString(DigestParamSet);
				publicKeyParameters.PublicKeyParamSet = Asn1ObjectIdentifier.FromOidString(PublicKeyParamSet);
				publicKeyParameters.EncryptionParamSet = CreateEncryptionParamSet(EncryptionParamSet);

				var asnEncoder = new Asn1BerEncodeBuffer();
				publicKeyParameters.Encode(asnEncoder);
				data = asnEncoder.MsgCopy;
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1EncodeError, typeof(GostR34102001PublicKeyParameters).FullName);
			}

			return data;
		}


		public void DecodePublicKey(byte[] data)
		{
			if (data == null)
			{
				throw ExceptionUtility.ArgumentNull("data");
			}

			try
			{
				var asnDecoder = new Asn1BerDecodeBuffer(data);
				var publicKey = new GostR34102001PublicKey();
				publicKey.Decode(asnDecoder);

				PublicKey = publicKey.Value;
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, typeof(GostR34102001PublicKey).FullName);
			}
		}


		private static Gost2814789ParamSet CreateEncryptionParamSet(string value)
		{
			return (value != null) ? new Gost2814789ParamSet(Asn1ObjectIdentifier.FromOidString(value).Value) : null;
		}
	}
}